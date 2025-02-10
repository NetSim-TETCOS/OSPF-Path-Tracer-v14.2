import pandas as pd
import networkx as nx
import sys
import re
import os
import subprocess
from matplotlib.lines import Line2D
from matplotlib import pyplot as plt
from matplotlib.patches import FancyArrowPatch, PathPatch
import ipywidgets as widgets
from IPython.display import display
from matplotlib.path import Path

ip_addr = []
grid_width = 500
grid_height = 500
device_name = []
device_id = []
device_type = []
app_id = []
app_name = []
routes = []
app_source = []
app_dest = []
link_id =[]
link_dev_count = []
link_devices = {}
node_x = []
node_y = []
color_map = []
labels = []
pos={}
allowed_types = ["Router", "WiredNode", "L2_Switch", "L3_Switch","Accesspoint","WirelessNode"]
#Function to read Configuration.netsim file and identify node name, Position Coordinates and IP Address
def config_reader(device_id,flag):
    device_name=""
    l_flag=0
    if not (os.path.isfile('Configuration.netsim')):
        print("Error: Configuration.netsim file missing in path: "+sys.argv[1])
        exit()
    for i, line in enumerate(open('configuration.netsim')):
            try:
                if l_flag==0:
                    found=re.search("<DEVICE KEY=\"(.+?)\" DEVICE_NAME=\"(.+?)\" DEVICE_ID=\"(.+?)\" TYPE=\"(.+?)\" INTERFACE_COUNT=\"(.+?)\" DEVICE_ICON=\"(.+?)\">",line).group(1,2)

                    if device_id in found[1]:
                        device_type.append(found[0])
                        device_name.append(found[1])
                        l_flag+=1
                        #print(found)
                else:
                    found=re.search("<POS_3D X_OR_LON=\"(.+?)\" Y_OR_LAT=\"(.+?)\" Z=\"(.+?)\" COORDINATE_SYSTEM=\"(.+?)\" ICON_ROTATION=\"(.+?)\" />",line).group(1,2)
                    #print(found)
                    if flag==1:
                        node_x.append(int(float(found[0])))
                        node_y.append(int(float(found[1])))
                    l_flag+=1                               
                    break

            except AttributeError:
                pass
    return device_name

#Function to read PCAP file and identify the first calculated Rank value of the node from the DIO message    
def get_rank_from_pcap(filename,flag):
    rank=""
    command = [wireshark_install_path, '-r', filename, '-T', 'fields', '-R', 'icmpv6.code==1', '-Y', 'ipv6.src==' + ip_addr[-1], '-e', 'icmpv6.rpl.dio.rank', '-2']
    output = subprocess.check_output(command, stderr=subprocess.PIPE).decode()
    lines = output.splitlines()
    rank = lines[-1]   
    #print(command)
    #print(rank)
    if(flag==1):
        print("\nRank obtained from the PCAP log: "+str(int(rank)))
    return int(rank)

#Function to create node label based on node name from Configuration file and rank value from PCAP file(if exists)
def get_node_label(type,device,flag):
    node_label=""
    node=""
    if "SINKNODE" in type:
        #found=re.search("SINKNODE-(.+?)",device).group(1)
        found=device.replace("SINKNODE-","")
        #print("sinknode id: "+found)
        node=config_reader(found,"SINKNODE",flag)
        if(flag==1):
            print("\nIdentified "+ node +" in the Configuration file.")
        r=1
        node_label=(node+'(rank:'+str(r)+')')
    elif "SENSOR" in type:
        #found=re.search("SENSOR-(.+?)",device).group(1)
        found=device.replace("SENSOR-","")
        #print("removed prefix "+device)
        #print("sensor id: "+found)
        node=config_reader(found,"SENSOR",flag)
        if(flag==1):
            print("\nIdentified "+ node +" in the Configuration file.")
        r=0
        if(os.path.isfile(node+'_1.pcap')):
            r=get_rank_from_pcap(sys.argv[1]+'\\'+node+'_1.pcap',flag);
            node_label=(node+'(rank:'+str(r)+')')
        else:
            node_label=(node)
    else:
        print("unknown device type")
    return ('\n\n\n'+node_label)


def analyze_packet_routes(trace_data: pd.DataFrame, app_name_list: list) -> list:
    """
    Analyzes packet trace data to identify routes for each application,
    handling duplicates and retransmissions.
    
    Args:
        trace_data: DataFrame containing packet trace data
        app_name_list: List of application names to analyze
    
    Returns:
        list: List of routes for each application
    """
    all_routes = []
    
    for app in app_name_list:
        # Filter data for current application
        app_data = trace_data[trace_data['CONTROL_PACKET_TYPE/APP_NAME'] == app]
        
        if app_data.empty:
            print(f"No data found for application: {app}")
            all_routes.append([])
            continue
        
        # Initialize variables for route finding
        current_route = []
        found_complete_route = False
        
        # Get all packet IDs for this application, sorted
        packet_ids = sorted(app_data['PACKET_ID'].unique())
        
        for packet_id in packet_ids:
            if found_complete_route:
                break
                
            # Filter data for current packet ID
            route_data = app_data[app_data['PACKET_ID'] == packet_id]
            
            if route_data.empty:
                continue
            
            # Get source and destination from first entry
            source_id = route_data.iloc[0]['SOURCE_ID']
            final_dest_id = route_data.iloc[0]['DESTINATION_ID']
            
            # Reset route tracking for new packet
            current_route = []
            current_transmitter = source_id
            processed_transmitters = set()  # Track processed transmitters for this packet
            
            while not found_complete_route:
                # Find all rows where transmitter matches current_transmitter
                matching_rows = route_data[route_data['TRANSMITTER_ID'] == current_transmitter]
                
                if matching_rows.empty:
                    # No matching transmitter found, break to try next packet
                    break
                
                # Sort matching rows by timestamp (assuming earlier transmissions should be processed first)
                matching_rows = matching_rows.sort_values('PACKET_ID')
                
                found_valid_transmission = False
                
                for _, row in matching_rows.iterrows():
                    current_receiver = row['RECEIVER_ID']
                    
                    # Skip if this transmitter-receiver pair has been processed
                    transmitter_receiver_pair = (current_transmitter, current_receiver)
                    if transmitter_receiver_pair in processed_transmitters:
                        continue
                        
                    # Add this hop to the route if it's not already there
                    if not current_route or current_route[-1] != current_transmitter:
                        current_route.append(current_transmitter)
                    if current_route[-1] != current_receiver:
                        current_route.append(current_receiver)
                    
                    # Mark this transmission as processed
                    processed_transmitters.add(transmitter_receiver_pair)
                    found_valid_transmission = True
                    
                    # Check if we've reached the destination
                    if current_receiver == final_dest_id:
                        found_complete_route = True
                        break
                    
                    # Set up for next iteration
                    current_transmitter = current_receiver
                    break  # Process only the first valid transmission
                
                if not found_valid_transmission:
                    # If no valid transmission found, break to try next packet
                    break
                
                if found_complete_route:
                    break
        
        # Remove any duplicate nodes in the final route
        final_route = []
        for node in current_route:
            if not final_route or final_route[-1] != node:
                final_route.append(node)
        
        all_routes.append(final_route)
    
    return all_routes

def process_packet_trace(trace_path: str, app_names: list) -> list:
    """
    Process packet trace file and identify routes for each application.
    
    Args:
        trace_path: Path to the packet trace CSV file
        app_names: List of application names to analyze
    
    Returns:
        list: List of routes for each application
    """
    try:
        # Read the CSV file in chunks
        chunks = []
        columns = ["PACKET_ID", "CONTROL_PACKET_TYPE/APP_NAME", 
                  "SOURCE_ID", "DESTINATION_ID", 
                  "TRANSMITTER_ID", "RECEIVER_ID"]
        
        for chunk in pd.read_csv(trace_path, 
                               usecols=columns,
                               iterator=True, 
                               chunksize=1000,
                               encoding="iso-8859-1"):
            chunks.append(chunk)
        
        # Concatenate all chunks
        trace_data = pd.concat(chunks, ignore_index=True)
        
        # Analyze routes
        routes = analyze_packet_routes(trace_data, app_names)
        
        return routes
        
    except Exception as e:
        print(f"Error processing packet trace: {str(e)}")
        return []

# Check if the file path argument is provided
if len(sys.argv) != 2:
    # Print error message with usage format
    print("Error: Incorrect number of arguments.")
    print("Usage: OSPF_Path_Tracer <path_to_experiment_folder>")
    sys.exit(1)  # Exit the program with an error code

# Get the file path argument
file_path = sys.argv[1]

os.chdir(file_path)
configpath = file_path+'\\Configuration.netsim'

#Configuration file Reading

if not (os.path.isfile('Configuration.netsim')):
        print("Error: Configuration.netsim file missing in path: "+sys.argv[1])
        exit()

#GRID SETTINGS
for i, line in enumerate(open('configuration.netsim')):
        try:
            found=re.search("<GRID_LENGTH>(.+?)</GRID_LENGTH>",line).group(1)
            grid_height = int(found)
            #print(found)

        except AttributeError:
            pass

#DEVICE_CONFIGURATION
#Router
l_flag=0
for i, line in enumerate(open('configuration.netsim')):
        try:
            if l_flag==0:
                found=re.search("<DEVICE KEY=\"(.+?)\" DEVICE_NAME=\"(.+?)\" TYPE=\"(.+?)\" DEVICE_ID=\"(.+?)\" WIRESHARK_OPTION=\"(.+?)\" INTERFACE_COUNT=\"(.+?)\" DEVICE_ICON=\"(.+?)\">",line).group(1,2,3,4)
                if found[0] in allowed_types:
                    device_type.append(found[0])
                    device_name.append(found[1])
                    device_id.append(found[3])
                    l_flag+=1
                #print(found)
            else:
                found=re.search("<POS_3D X_OR_LON=\"(.+?)\" Y_OR_LAT=\"(.+?)\" Z=\"(.+?)\" COORDINATE_SYSTEM=\"(.+?)\" ICON_ROTATION=\"(.+?)\" />",line).group(1,2)
                #print(found)
                node_x.append(int(float(found[0])))
                node_y.append(int(float(found[1])))
                l_flag=0                              
                

        except AttributeError:
            pass
#Others
l_flag=0
for i, line in enumerate(open('configuration.netsim')):
        try:
            if l_flag==0:
                found=re.search("<DEVICE KEY=\"(.+?)\" DEVICE_NAME=\"(.+?)\" DEVICE_ID=\"(.+?)\" TYPE=\"(.+?)\" WIRESHARK_OPTION=\"(.+?)\" INTERFACE_COUNT=\"(.+?)\" DEVICE_ICON=\"(.+?)\">",line).group(1,2,3)
                if found[0] in allowed_types:
                    device_type.append(found[0])
                    device_name.append(found[1])
                    device_id.append(found[2])
                    l_flag+=1
                #print(found)
            else:
                found=re.search("<POS_3D X_OR_LON=\"(.+?)\" Y_OR_LAT=\"(.+?)\" Z=\"(.+?)\" COORDINATE_SYSTEM=\"(.+?)\" ICON_ROTATION=\"(.+?)\" />",line).group(1,2)
                #print(found)
                node_x.append(int(float(found[0])))
                node_y.append(int(float(found[1])))
                l_flag=0                              
                

        except AttributeError:
            pass
#Switch
l_flag=0
for i, line in enumerate(open('configuration.netsim')):
        try:
            if l_flag==0:
                found=re.search("<DEVICE KEY=\"(.+?)\" DEVICE_NAME=\"(.+?)\" DEVICE_ID=\"(.+?)\" TYPE=\"(.+?)\" INTERFACE_COUNT=\"(.+?)\" DEVICE_ICON=\"(.+?)\">",line).group(1,2,3)
                if found[0] in allowed_types:
                    device_type.append(found[0])
                    device_name.append(found[1])
                    device_id.append(found[2])
                    l_flag+=1
                #print(found)
            else:
                found=re.search("<POS_3D X_OR_LON=\"(.+?)\" Y_OR_LAT=\"(.+?)\" Z=\"(.+?)\" COORDINATE_SYSTEM=\"(.+?)\" ICON_ROTATION=\"(.+?)\" />",line).group(1,2)
                #print(found)
                node_x.append(int(float(found[0])))
                node_y.append(int(float(found[1])))
                l_flag=0                              
                

        except AttributeError:
            pass
# #CONNECTION
# l_flag=0
# for i, line in enumerate(open('configuration.netsim')):
#         try:
#             if l_flag==0:
#                 found=re.search("<LINK LINK_ID=\"(.+?)\" LINK_NAME=\"(.+?)\" DEVICE_COUNT=\"(.+?)\" KEY=\"(.+?)\" TYPE=\"(.+?)\" MEDIUM=\"(.+?)\" LINK_MODE=\"(.+?)\" LINK_SPEED_UP=\"(.+?)\" LINK_SPEED_DOWN=\"(.+?)\">",line).group(1,2,3)
#                 link_id.append(found[0])
#                 link_dev_count.append(int(found[2]))
#                 link_devices[found[0]] = []  # Initialize the list for this link_id
#                 l_flag+=1
#                 #print(found)
#             else:
#                 last_Value = link_dev_count[-1]  # Replace this with your desired value
#                 for i in range(last_Value):
#                     found=re.search("<DEVICE DEVICE_ID=\"(.+?)\" INTERFACE_ID=\"(.+?)\" NAME=\"(.+?)\" />",line).group(1,2,3)
#                     link_devices[link_id[-1]].append(found[2])
#                     #print(found)
#                     l_flag=0                               
                    

#         except AttributeError:
#             pass
# CONNECTION
l_flag = 0
with open('configuration.netsim') as file:
    lines = file.readlines()
    for i, line in enumerate(lines):
        try:
            if l_flag == 0:
                match = re.search(r'<LINK LINK_ID="(.+?)" LINK_NAME="(.+?)" DEVICE_COUNT="(.+?)" KEY="(.+?)" TYPE="(.+?)" MEDIUM="(.+?)" LINK_MODE="(.+?)" LINK_SPEED_UP="(.+?)" LINK_SPEED_DOWN="(.+?)">', line)
                if match:
                    found = match.group(1, 2, 3)
                    link_id.append(found[0])
                    link_dev_count.append(int(found[2]))
                    link_devices[found[0]] = []  # Initialize the list for this link_id
                    l_flag += 1
            else:
                last_Value = link_dev_count[-1]
                device_count = 0
                for j in range(i + 1, len(lines)):
                    device_line = lines[j]
                    match = re.search(r'<DEVICE DEVICE_ID="(.+?)" INTERFACE_ID="(.+?)" NAME="(.+?)" />', device_line)
                    if match:
                        found = match.group(1, 2, 3)
                        link_devices[link_id[-1]].append(found[2])
                        device_count += 1
                        if device_count == last_Value:
                            break
                l_flag = 0  # Reset the flag after processing the devices
        except AttributeError:
            pass
#APPLICATION_CONFIGURATION
for i, line in enumerate(open('configuration.netsim')):
        try:
            found=re.search("<APPLICATION KEY=\"(.+?)\" APPLICATION_METHOD=\"(.+?)\" APPLICATION_TYPE=\"(.+?)\" ID=\"(.+?)\" NAME=\"(.+?)\" SOURCE_COUNT=\"(.+?)\" SOURCE_ID=\"(.+?)\" DESTINATION_COUNT=\"(.+?)\" DESTINATION_ID=\"(.+?)\"",line).group(1,2,3,4,5,6,7,8,9)
            app_id.append(found[3])
            app_name.append(found[4])
            app_source.append(found[6])
            app_dest.append(found[8])
            #print(found)

        except AttributeError:
            pass

#Packet Trace Log file

tracepath = 'Packet Trace.csv'

if not (os.path.isfile(tracepath)):
    print("Error: Packet Trace.csv file missing in path: "+sys.argv[1])
    exit()

# Example usage with your variables:
routes = process_packet_trace(tracepath, app_name)
for idx, route in enumerate(routes):
    print(f"Route for {app_name[idx]}: {' -> '.join(route)}")

# Define node shapes and colors based on device type
node_shapes = {
    'Router': 'o',        # Circle
    'WiredNode': 's',     # Square
    'L2_Switch': 'D',     # Diamond
    'L3_Switch': '^',     # Triangle Up
    'Accesspoint': 'p',   # Pentagon
    'WirelessNode': '*'   # Star
}
node_colors = {
    'Router': 'red',
    'WiredNode': 'blue',
    'L2_Switch': 'green',
    'L3_Switch': 'purple',
    'Accesspoint': 'orange',
    'WirelessNode': 'cyan'
}

# Define different colors for each application flow
app_flow_colors = ['orange', 'cyan', 'magenta', 'yellow', 'lime', 'red', 'blue', 'green', 'purple', 'pink', 'brown', 'teal', 'violet', 'indigo', 'black', 'white']  # Add more colors if needed

# Create the flow diagram
fig, ax = plt.subplots(figsize=(10, 8))
G = nx.Graph()

# Create a mapping of device names to their types for easy lookup
device_type_map = {name: type_ for name, type_ in zip(device_name, device_type)}

# Add nodes with positions, names, shapes, and colors
for i, name in enumerate(device_name):
    G.add_node(
        name, 
        **{
            'pos': (node_x[i], node_y[i]),
            'shape': node_shapes[device_type[i]],
            'color': node_colors[device_type[i]],
            'type': device_type[i]
        }
    )

# Add edges based on link_devices, only if both devices are of allowed types
for link, devices in link_devices.items():
    if len(devices) == 2:
        device1, device2 = devices
        type1 = device_type_map[device1]
        type2 = device_type_map[device2]
        
        if type1 in allowed_types and type2 in allowed_types:
            G.add_edge(device1, device2)

# Get node positions
pos = nx.get_node_attributes(G, 'pos')

# Create position dictionary for labels (shifted below nodes)
label_pos = {node: (x, y + ((grid_height/100)*2)) for node, (x, y) in pos.items()}

# Draw nodes with different shapes and colors
for shape in set(node_shapes.values()):
    nodes_with_shape = [node for node, data in G.nodes(data=True) if data.get('shape') == shape]
    colors_with_shape = [G.nodes[node]['color'] for node in nodes_with_shape]
    
    nx.draw_networkx_nodes(
        G, pos,
        nodelist=nodes_with_shape,
        node_shape=shape,
        node_color=colors_with_shape,
        node_size=50,
        ax=ax
    )

# Draw edges
nx.draw_networkx_edges(G, pos, ax=ax)

# Draw node labels below the shapes
nx.draw_networkx_labels(
    G, 
    label_pos,
    font_size=10,
    verticalalignment='top',
    ax=ax
)

# Function to draw curved edges with arrows
def draw_curved_edge(pos, p1, p2, color, style, rad):
    x1, y1 = pos[p1]
    x2, y2 = pos[p2]
    # Define Bezier curve control point for curvature
    cx = (x1 + x2) / 2 + rad * (y2 - y1)
    cy = (y1 + y2) / 2 - rad * (x2 - x1)

    # Define curved path using Bezier control points
    path = Path([(x1, y1), (cx, cy), (x2, y2)], [Path.MOVETO, Path.CURVE3, Path.CURVE3])
    
    # Draw the curved line without an arrow
    patch = PathPatch(path, edgecolor=color, linestyle=style, linewidth=2, facecolor='none')
    ax.add_patch(patch)

    # Calculate midpoint along the curve
    t = 0.5  # Midpoint parameter in Bezier curve
    xm = (1 - t) ** 2 * x1 + 2 * (1 - t) * t * cx + t ** 2 * x2
    ym = (1 - t) ** 2 * y1 + 2 * (1 - t) * t * cy + t ** 2 * y2

    # Small offset for minimal arrow shaft
    offset_factor = 0.02
    x_start = xm - (x2 - x1) * offset_factor
    y_start = ym - (y2 - y1) * offset_factor

    # Draw only the arrowhead at the midpoint
    arrow = FancyArrowPatch((x_start, y_start), (xm, ym), 
                             color=color, linewidth=2, 
                             arrowstyle='-|>', mutation_scale=15)

    ax.add_patch(arrow)

# Function to draw straight edges with arrows
def draw_straight_edge(pos, p1, p2, color, style):
    x1, y1 = pos[p1]
    x2, y2 = pos[p2]
    # Draw the straight dotted line without an arrow
    ax.plot([x1, x2], [y1, y2], color=color, linestyle=style, linewidth=1)

    # Calculate the midpoint
    xm, ym = (x1 + x2) / 2, (y1 + y2) / 2

    # Define a very small offset to keep the arrow's shaft nearly invisible
    offset_factor = 0.02  # Adjust to control arrow shaft length
    x_start = xm - (x2 - x1) * offset_factor
    y_start = ym - (y2 - y1) * offset_factor

    # Draw only the arrowhead at the midpoint with a near-zero shaft
    arrow = FancyArrowPatch((x_start, y_start), (xm, ym), 
                             color=color, linewidth=1, 
                             arrowstyle='-|>', mutation_scale=15)

    ax.add_patch(arrow)

# Draw application flows with dotted lines and arrows in different colors
for idx, (src, dest) in enumerate(zip(app_source, app_dest)):
    src_name = device_name[device_id.index(src)]
    dest_name = device_name[device_id.index(dest)]
    
    # Draw the flow line with a distinct color and dotted style
    draw_straight_edge(pos, src_name, dest_name, app_flow_colors[idx % len(app_flow_colors)], 'dotted')

# Draw routes with curved thick lines using the same color as the application flow
for idx, route in enumerate(routes):
    # Process the route to extract device IDs
    dev = [r.split('-')[1] for r in route]
    
    # Create route edges using the processed device IDs
    for i in range(len(dev) - 1):
        draw_curved_edge(pos, device_name[device_id.index(dev[i])], device_name[device_id.index(dev[i+1])], app_flow_colors[idx % len(app_flow_colors)], 'solid', 0.3 + 0.1 * idx)

# Invert y-axis
ax.invert_yaxis()

# Add some padding to the plot
plt.margins(0.2)

# Create custom legend handles
legend_handles = []
for idx, app in enumerate(app_name):
    legend_handles.append(Line2D([0], [0], color=app_flow_colors[idx % len(app_flow_colors)], linestyle='dotted', linewidth=2, label=f'App {idx+1}: {app}'))
    legend_handles.append(Line2D([0], [0], color=app_flow_colors[idx % len(app_flow_colors)], linestyle='solid', linewidth=2, label=f'Route App {idx+1}'))

# Add legend
ax.legend(handles=legend_handles)

# Set plot title
plt.title("Network Application Flow Diagram")
fig.canvas.manager.set_window_title("OSPF Path Tracer")
# Show plot
plt.show(block=True)  # Keep the plot window open