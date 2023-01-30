import os
import sys
import pickle as pickle
import numpy as np
import pandas as pd
pd.options.mode.chained_assignment = None  # default='warn'
from sklearn import tree
import re
from statistics import mode
import random

np.random.seed(42)

## import and get entries from trained models ##
clf = pd.read_pickle('unsw_per_flow_saved_model_16_classes.sav') ## replace with saved RF model file in .sav format

## list the feature names
feature_names = clf.feature_names_in_
print(feature_names)

## definition of useful functions
## gets all splits and conditions
def get_splits(forest, feature_names):
    data = []
    #generate dataframe with all thresholds and features
    for t in range(len(forest.estimators_)):
        clf = forest[t]
        n_nodes = clf.tree_.node_count
        features  = [feature_names[i] for i in clf.tree_.feature]
        for i in range(0, n_nodes):
            node_id = i
            left_child_id = clf.tree_.children_left[i]
            right_child_id = clf.tree_.children_right[i]
            threshold = clf.tree_.threshold[i]
            feature = features[i]
            if threshold != -2.0:
                data.append([t, node_id, left_child_id,
                             right_child_id, threshold, feature])
    data = pd.DataFrame(data)
    data.columns = ["Tree","NodeID","LeftID","RightID","Threshold","Feature"]
    return data

## gets the feature table of each feature from the splits
def get_feature_table(splits_data, feature_name):
    feature_data = splits_data[splits_data["Feature"]==feature_name]
    feature_data = feature_data.sort_values(by="Threshold")
    feature_data = feature_data.reset_index(drop=True)
    ##
    # feature_data["Threshold"] = (feature_data["Threshold"]).astype(int)
    feature_data["Threshold"] = feature_data["Threshold"].astype(int)
    ##
    code_table = pd.DataFrame()
    code_table["Threshold"] = feature_data["Threshold"]
    #print(feature_data)
    #create a column for each split in each tree
    for tree_id, node in zip(list(feature_data["Tree"]), list(feature_data["NodeID"])):
        colname = "s"+str(tree_id)+"_"+str(node)
        code_table[colname] = np.where((code_table["Threshold"] <=
                                        feature_data[(feature_data["NodeID"]== node) &
                                                     (feature_data["Tree"]==tree_id)]["Threshold"].values[0]), 0, 1)
    #add a row to represent the values above the largest threshold
    temp = [max(code_table["Threshold"])+1]
    temp.extend(list([1]*(len(code_table.columns)-1)))
    code_table.loc[len(code_table)] = temp
    code_table = code_table.drop_duplicates(subset=['Threshold'])
    code_table = code_table.reset_index(drop=True)
    return code_table

## get feature tables with ranges and codes only
def get_feature_codes_with_ranges(feature_table, num_of_trees):
    Codes = pd.DataFrame()
    for tree_id in range(num_of_trees):
        colname = "code"+str(tree_id)
        Codes[colname] = feature_table[feature_table[[col for col in feature_table.columns if ('s'+str(tree_id)+'_') in col]].columns[0:]].apply(lambda x: ''.join(x.dropna().astype(str)),axis=1)
        Codes[colname] = ["0b" + x for x in Codes[colname]]
    feature_table["Range"] = [0]*len(feature_table)
    feature_table["Range"].loc[0] = "0,"+str(feature_table["Threshold"].loc[0])
    for i in range(1, len(feature_table)):
        if (i==(len(feature_table))-1):
            feature_table["Range"].loc[i] = str(feature_table["Threshold"].loc[i])+","+str(feature_table["Threshold"].loc[i])
        else:
            feature_table["Range"].loc[i] = str(feature_table["Threshold"].loc[i-1]+1) + ","+str(feature_table["Threshold"].loc[i])
    Ranges = feature_table["Range"]
    return Ranges, Codes

## get list of splits crossed to get to leaves
def retrieve_branches(estimator):
    number_nodes = estimator.tree_.node_count
    children_left_list = estimator.tree_.children_left
    children_right_list = estimator.tree_.children_right
    feature = estimator.tree_.feature
    threshold = estimator.tree_.threshold
    # Calculate if a node is a leaf
    is_leaves_list = [(False if cl != cr else True) for cl, cr in zip(children_left_list, children_right_list)]
    # Store the branches paths
    paths = []
    for i in range(number_nodes):
        if is_leaves_list[i]:
            # Search leaf node in previous paths
            end_node = [path[-1] for path in paths]
            # If it is a leave node yield the path
            if i in end_node:
                output = paths.pop(np.argwhere(i == np.array(end_node))[0][0])
                yield output
        else:
            # Origin and end nodes
            origin, end_l, end_r = i, children_left_list[i], children_right_list[i]
            # Iterate over previous paths to add nodes
            for index, path in enumerate(paths):
                if origin == path[-1]:
                    paths[index] = path + [end_l]
                    paths.append(path + [end_r])
            # Initialize path in first iteration
            if i == 0:
                paths.append([i, children_left_list[i]])
                paths.append([i, children_right_list[i]])

## get classes and certainties
def get_classes(clf):
    leaves = []
    classes = []
    certainties = []
    for branch in list(retrieve_branches(clf)):
        leaves.append(branch[-1])
    for leaf in leaves:
        if clf.tree_.n_outputs == 1:
            value = clf.tree_.value[leaf][0]
        else:
            value = clf.tree_.value[leaf].T[0]
        class_name = np.argmax(value)
        certainty = int(round(max(value)/sum(value),2)*100)
        classes.append(class_name)
        certainties.append(certainty)
    return classes, certainties

## get the codes corresponging to the branches followed
def get_leaf_paths(clf):
    depth = clf.max_depth
    branch_codes = []
    for branch in list(retrieve_branches(clf)):
        code = [0]*len(branch)
        for i in range(1, len(branch)):
            if (branch[i]==clf.tree_.children_left[branch[i-1]]):
                code[i] = 0
            elif (branch[i]==clf.tree_.children_right[branch[i-1]]):
                code[i] = 1
        branch_codes.append(list(code[1:]))
    return branch_codes

## get the order of the splits to enable code generation
def get_order_of_splits(data, feature_names):
    splits_order = []
    for feature_name in feature_names:
        feature_data = data[data.iloc[:,4]==feature_name]
        feature_data = feature_data.sort_values(by="Threshold")
        for node in list(feature_data.iloc[:,0]):
            splits_order.append(node)
    return splits_order

def get_splits_per_tree(clf, feature_names):
    data = []
    n_nodes = clf.tree_.node_count
    #set feature names
    features  = [feature_names[i] for i in clf.tree_.feature]
    #generate dataframe with all thresholds and features
    for i in range(0,n_nodes):
        node_id = i
        left_child_id = clf.tree_.children_left[i]
        right_child_id = clf.tree_.children_right[i]
        threshold = clf.tree_.threshold[i]
        feature = features[i]
        if threshold != -2.0:
            data.append([node_id, left_child_id,
                         right_child_id, threshold, feature])
    data = pd.DataFrame(data)
    data.columns = ["NodeID","LeftID","RightID","Threshold","Feature"]
    return data

## Get codes and masks
def get_codes_and_masks(clf, feature_names):
    splits = get_order_of_splits(get_splits_per_tree(clf, feature_names), feature_names)
    depth = clf.max_depth
    codes = []
    masks = []
    for branch, coded in zip(list(retrieve_branches(clf)), get_leaf_paths(clf)):
        code = [0]*len(splits)
        mask = [0]*len(splits)
        for index, split in enumerate(splits):
            if split in branch:
                mask[index] = 1
        masks.append(mask)
        codes.append(code)
    masks = pd.DataFrame(masks)
    masks['Mask'] = masks[masks.columns[0:]].apply(lambda x: ''.join(x.dropna().astype(str)),axis=1)
    masks = ["0b" + x for x in masks['Mask']]
    indices = range(0,len(splits))
    temp = pd.DataFrame(columns=["split", "index"],dtype=object)
    temp["split"] = splits
    temp["index"] = indices
    final_codes = []
    for branch, code, coded in zip(list(retrieve_branches(clf)), codes, get_leaf_paths(clf)):
        indices_to_use = temp[temp["split"].isin(branch)].sort_values(by="split")["index"]
        for i, j in zip(range(0,len(coded)), list(indices_to_use)):
            code[j] = coded[i]
        final_codes.append(code)
    final_codes = pd.DataFrame(final_codes)
    final_codes["Code"] = final_codes[final_codes.columns[0:]].apply(lambda x: ''.join(x.dropna().astype(str)),axis=1)
    final_codes = ["0b" + x for x in final_codes["Code"]]
    return final_codes, masks
## End of model manipulation ##

# Get table entries and generate file with table entries
with open("te_unsw_per_flow_saved_model_16_classes.py", "w") as entries_file: # replace .py filename with desired table entries output filename

    print("p4 = bfrt.unsw_per_flow_16_classes.pipe\n", file=entries_file) # replace unsw_per_flow_16_classes with p4 file name

    clear_tables = """
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
    for table_types in (['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR'],
                        ['SELECTOR'],
                        ['ACTION_PROFILE']):
        for table in p4.info(return_info=True, print_info=False):
            if table['type'] in table_types:
                if verbose:
                    print("Clearing table {:<40} ... ".
                          format(table['full_name']), end='', flush=True)
                table['node'].clear(batch=batching)
                if verbose:
                    print('Done')
"""

    port_setup = """
# This script configures QSFP ports automatically on the TOFINO Switch
# Adapted from ICA-1131 Intel Connectivity Academy Course
for qsfp_cage in [1, 5]:
    for lane in range(0, 1):
        dp = bfrt.port.port_hdl_info.get(CONN_ID = qsfp_cage, CHNL_ID = lane, print_ents = False).data[b'$DEV_PORT']
        bfrt.port.port.add(DEV_PORT= dp, SPEED = "BF_SPEED_100G", FEC = "BF_FEC_TYP_NONE", AUTO_NEGOTIATION = "PM_AN_FORCE_DISABLE", PORT_ENABLE = True)
"""
    print(port_setup, file=entries_file)

    print(clear_tables, file=entries_file)

    print("clear_all(verbose=True)\n", file=entries_file)
    print("voting_table = p4.Ingress.voting_table", file=entries_file)

    for num_feat in range(len(feature_names)):
            print("table_feature"+str(num_feat)+" = p4.Ingress.table_feature"+str(num_feat), file=entries_file)
    print('', file=entries_file)

    for num_tree in range(len(clf.estimators_)):
        print("code_table"+str(num_tree)+" = p4.Ingress.code_table"+str(num_tree), file=entries_file)
    print('', file=entries_file)

    # Get entries for feature tables
    tree_code0 = []
    tree_code1 = []
    tree_code2 = []

    for fea in range(0,len(feature_names)):
        Ranges, Codes = get_feature_codes_with_ranges(get_feature_table(get_splits(clf, feature_names), feature_names[fea]), len(clf.estimators_))
        for ran, cods0, cods1, cods2 in zip(Ranges, Codes.iloc[:,0], Codes.iloc[:,1], Codes.iloc[:,2]):
            if(ran == Ranges[len(Ranges)-1]):
                print("table_feature"+str(fea)+".add_with_SetCode"+str(fea)+"(feature"+str(fea)+"_start="+str(ran.split(",")[0])+ \
                ", feature"+str(fea)+"_end="+str(65535)+", code0="+str(cods0) + ", code1=" + str(cods1) + ", code2=" + str(cods2) + ")", file = entries_file)
            else:
                print("table_feature"+str(fea)+".add_with_SetCode"+str(fea)+"(feature"+str(fea)+"_start="+str(ran.split(",")[0])+ \
                ", feature"+str(fea)+"_end="+str(ran.split(",")[1])+", code0="+str(cods0)+", code1="+str(cods1)+", code2=" +str(cods2) + ")", file = entries_file)
        tree_code0.append(len(cods0)-2)
        tree_code1.append(len(cods1)-2)
        tree_code2.append(len(cods2)-2)

        print('', file=entries_file)
    tree_code_sizes = [tree_code0, tree_code1, tree_code2]
    print(tree_code_sizes)

    print('print("******************* ENTERED FEATURE TABLE RULES *****************")\n',  file=entries_file)

    for tree_id in range(0, len(clf.estimators_)):
        Final_Codes, Final_Masks = get_codes_and_masks(clf.estimators_[tree_id], feature_names)
        Classe, Certain = get_classes(clf.estimators_[tree_id])
        for cod, mas, cla, cer in zip(Final_Codes, Final_Masks, Classe, Certain):
            print("code_table"+str(tree_id)+".add_with_SetClass"+str(tree_id)+"(codeword"+str(tree_id)+"=", cod, ", codeword"+str(tree_id)+"_mask=", mas, ", classe=",cla+1,")", file=entries_file)
        print('', file=entries_file)

    # Get voting table entries
    # This loop should be modified depending on number of trees (i, j, k for 3 trees) and number of classes (1 to 17 for 16 classes)
    for i in range(1,17):
        for j in range(1,17):
            for k in range(1,17):
                if ((i!=j) & (j!=k) & (i!=k)):
                    print("voting_table.add_with_set_final_class("+"class0="+str(i)+ \
                          ", class1="+str(j)+", class2="+str(k)+", class_result="+str(np.random.choice([i, j, k]))+")", file=entries_file)
                else:
                    print("voting_table.add_with_set_final_class("+"class0="+str(i)+", class1="+str(j)+\
                          ", class2="+str(k)+", class_result="+str(mode([i, j, k]))+")", file=entries_file)

    print("bfrt.complete_operations()", file=entries_file)

    # Final programming
    print('\nprint("******************* SAMPLE PROGAMMING RESULTS *****************")', file=entries_file)
    print('print("Table code0:")',          file=entries_file)
    print("code_table0.dump(table=True)",   file=entries_file)
    print('print("Table feature0:")',       file=entries_file)
    print("table_feature0.dump(table=True)",file=entries_file)

print("** TABLE ENTRIES GENERATED AND STORED IN DESIGNATED FILE **")
