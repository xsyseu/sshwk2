#!/usr/bin/python

import pefile
import sys
import argparse
import os
import pprint
import networkx
import re
from networkx.drawing.nx_agraph import write_dot
import collections
from networkx.algorithms import bipartite

args = argparse.ArgumentParser("Visualize shared hostnames between a directory of malware samples")
args.add_argument("target_path",help="directory with malware samples")
args.add_argument("output_file",help="file to write DOT file to")
args.add_argument("malware_projection",help="file to write DOT file to")
args.add_argument("hostname_projection",help="file to write DOT file to")
args = args.parse_args()
network = networkx.Graph()


def find_section(path):
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError:
        return []
    section = [str(sectionname.Name, "utf-8").strip() for sectionname in pe.sections]
    return section

# search the target directory for valid Windows PE executable files
for root,dirs,files in os.walk(args.target_path):
    for path in files:
        # try opening the file with pefile to see if it's really a PE file
        try:
            pe = pefile.PE(os.path.join(root,path))
        except pefile.PEFormatError:
            continue
        fullpath = os.path.join(root,path)
        sectionName = find_section(fullpath)
        # extract printable strings from the target sample
        # use the search_doc function in the included reg module to find hostnames
        if len(sectionName):
            # add the nodes and edges for the bipartite network
            network.add_node(path, label=path[:32], color='black', penwidth=5, bipartite=0)
        for section in sectionName:
            network.add_node(section, label=section, color='blue', penwidth=10, bipartite=1)
            network.add_edge(section, path, penwidth=2)
        if len(sectionName):
            print("Extracted sections from:", path)
            pprint.pprint(sectionName)
# write the dot file to disk
write_dot(network, args.output_file)
malware = set(n for n,d in network.nodes(data=True) if d['bipartite']==0)
hostname = set(network)-malware

# use NetworkX's bipartite network projection function to produce the malware
# and hostname projections
malware_network = bipartite.projected_graph(network, malware)
hostname_network = bipartite.projected_graph(network, hostname)

# write the projected networks to disk as specified by the user
write_dot(malware_network,args.malware_projection)
write_dot(hostname_network,args.hostname_projection)
