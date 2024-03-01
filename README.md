# Flowrest: Practical Flow-Level Inference in Programmable Switches with Random Forests

This repository contains the public version of the code for our work Flowrest which is published in the Proceedings of IEEE INFOCOM 2023, 17-20 May 2023, New York Area, USA.

An extended version of the paper will soon be available and we have updated this repository with a version of our code with all the functionalities described in the paper.

## Overview of the Flowrest system
<img src="flowrest.png" alt="Flowrest Overview" style="height: 370px; width:650px;"/>  

Flowrest is a practical framework that can run Random Forest (RF) models at flow-level in real-world programmable switches. It
enables the embedding of large RF models into production-grade programmable hardware, for challenging inference tasks
on individual traffic flows at line rate. Flowrest is implemented as open-source software using the P4 language.

For full details, please consult <a href="https://dspace.networks.imdea.org/handle/20.500.12761/1649">our paper</a>.

## Organization of the repository  
There are two folders:  
<!-- - _Data_ : information on how to access the data  -->
- _P4_ : the P4 code for Tofino
- _Python_ : the jupyter notebooks for training the machine learning models, the python scripts for generating the M/A table entries from the saved trained models and the control plane code.

In each folder, there are two sub-folders; one for the conference version of Flowrest and the other for the full version with all the functionalities fully implemented.

## Use cases
The use cases considered in the paper are: 
- IoT device identification task based on the publicly available <a href="https://iotanalytics.unsw.edu.au/iottraces.html">UNSW-IOT Traces</a>. <br>The challenge is to classify traffic into one of 16 or 26 classes. 
- Protocol classification with 8 protocol classes, based on the <a href="http://netweb.ing.unibs.it/~ntw/tools/traces/">UNIBS 2009 Internet Traces</a>.
- Intrusion detection system separating malware from benign traffic. <br> It is based on the <a href="https://www.unb.ca/cic/datasets/ids-2017.html">CICIDS 2017 Friday</a> dataset containing DDoS attacks and normal traffic.
- Bot classification with 10 attack classes and 4 benign classes. It is based on the <a href="https://www.stratosphereips.org/datasets-iot23">IoT-23 public traces</a>. The classification task is to distinguish 14 traffic classes
- IoT attack classification with 10 classes, based on the <a href="https://research.unsw.edu.au/projects/toniot-datasets">ToN-IoT network data</a>. 

For the conference version of the code, we provide the python and P4 code for the UNSW-IoT device identification use case with 16 classes. <br> The same approach for feature/model selection and encoding to P4 applies to all the use cases.

For the full version of the code, we provide the code for the CICIDS-2017 intrusion detection use case with 2 classes. <br> The same approach for feature/model selection and encoding to P4 applies to all the use cases.

You can access the train/test files for the examples above from this <a href="https://box.networks.imdea.org/s/xV7P5bunjxbiSh1">Box folder</a>.


## Citation
If you make use of this code, kindly cite our paper:  
```
@inproceedings{flowrest-2023,
author = {Akem, Aristide Tanyi-Jong and Gucciardo, Michele and Fiore, Marco},
title = {Flowrest: Practical Flow-Level Inference in Programmable Switches with Random Forests},
year = {2023},
publisher = {},
address = {},
doi = {10.1109/INFOCOM53939.2023.10229100},
booktitle = {INFOCOM 2023 - IEEE Conference on Computer Communications},
numpages = {10},
location = {New York, USA}
}
```

If you need any additional information, send us an email at _aristide.akem_ at _imdea.org_ or _beyza.butun_ at _imdea.org_.


