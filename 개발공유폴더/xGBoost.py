import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from xgboost import XGBClassifier  
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_recall_curve, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import os
import warnings
warnings.simplefilter('ignore')

df = pd.read_csv('./dataset_malwares.csv')
df1 = pd.read_csv('./dataset_test.csv')

dropped_df = df.drop(['Name','Malware'],axis=1)

features = ['e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc', 'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 
            'e_ip', 'e_cs', 'e_lfarlc', 'e_ovno', 'e_oemid', 'e_oeminfo', 'e_lfanew', 'Machine', 'NumberOfSections', 
            'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics', 
            'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 
            'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion', 
            'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion', 
            'SizeOfHeaders', 'CheckSum', 'SizeOfImage', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 
            'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes', 'SuspiciousImportFunctions', 
            'SuspiciousNameSection', 'SectionsLength', 'SectionMinEntropy', 'SectionMaxEntropy', 'SectionMinRawsize', 
            'SectionMaxRawsize', 'SectionMinVirtualsize', 'SectionMaxVirtualsize', 'SectionMaxPhysical', 'SectionMinPhysical', 
            'SectionMaxVirtual', 'SectionMinVirtual', 'SectionMaxPointerData', 'SectionMinPointerData', 'SectionMaxChar', 
            'SectionMainChar', 'DirectoryEntryImport', 'DirectoryEntryImportSize', 'DirectoryEntryExport', 'ImageDirectoryEntryExport', 
            'ImageDirectoryEntryImport', 'ImageDirectoryEntryResource', 'ImageDirectoryEntryException', 'ImageDirectoryEntrySecurity']

x = dropped_df
y = df['Malware']

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
x_scaled = scaler.fit_transform(x_train)
x_new = pd.DataFrame(x_scaled, columns=x.columns)

skpca = PCA(n_components=55)
x_pca = skpca.fit_transform(x_new)
print('Variance sum : ', skpca.explained_variance_.cumsum()[-1])

model = XGBClassifier(
    n_estimators=100,          
    random_state=42,           
    max_depth=16,              
    objective='binary:logistic', 
    eval_metric='logloss',     
    use_label_encoder=False    
)

model.fit(x_pca, y_train)

x_test_scaled = scaler.transform(x_test)
x_new_test = pd.DataFrame(x_test_scaled, columns=x.columns)
x_test_pca = skpca.transform(x_new_test)

y_pred = model.predict(x_test_pca)
print(classification_report(y_pred, y_test))

y_test_proba = model.predict_proba(x_test_pca)[:, 1]  

precision, recall, thresholds = precision_recall_curve(y_test, y_test_proba)
f1_scores = 2 * (precision * recall) / (precision + recall + 1e-8)  

best_threshold = thresholds[np.argmax(f1_scores)]

y_test_pred = (y_test_proba >= best_threshold).astype(int)

pipe = Pipeline([('scale', scaler), ('pca', skpca), ('clf', model)])
x_testing = df1.drop('Name', axis=1)

x_testing_scaled = pipe.named_steps['scale'].transform(x_testing)
x_testing_pca = pipe.named_steps['pca'].transform(x_testing_scaled)
y_testing_pred = pipe.named_steps['clf'].predict_proba(x_testing_pca)

y_proba = y_testing_pred[:, 1]
malware_pred = (y_proba >= best_threshold)

filtered_results = pd.DataFrame(y_testing_pred, columns=[f'Class_{i}' for i in range(y_testing_pred.shape[1])])
filtered_results_with_names = pd.concat([df1['Name'], filtered_results], axis=1)
filtered_results_with_names = filtered_results_with_names[filtered_results_with_names['Class_1'] >= best_threshold]

print(filtered_results_with_names)

filtered_names = filtered_results_with_names['Name']

filtered_names.to_csv('xgboost_datas.csv', index=False)

