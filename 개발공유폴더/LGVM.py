import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import precision_recall_curve, f1_score
import os
import warnings
warnings.simplefilter('ignore')

df = pd.read_csv('./dataset_malwares.csv')
df1 = pd.read_csv('./dataset_test.csv')

dropped_df = df.drop(['Name','Malware'],axis=1)

features = ['e_magic','e_cblp','e_cp','e_crlc','e_cparhdr','e_minalloc','e_maxalloc','e_ss','e_sp','e_csum','e_ip','e_cs','e_lfarlc','e_ovno','e_oemid','e_oeminfo',
            'e_lfanew','Machine','NumberOfSections','TimeDateStamp','PointerToSymbolTable','NumberOfSymbols','SizeOfOptionalHeader','Characteristics',
            'Magic','MajorLinkerVersion','MinorLinkerVersion','SizeOfCode','SizeOfInitializedData','SizeOfUninitializedData','AddressOfEntryPoint',
            'BaseOfCode','ImageBase','SectionAlignment','FileAlignment','MajorOperatingSystemVersion','MinorOperatingSystemVersion','MajorImageVersion',
            'MinorImageVersion','MajorSubsystemVersion','MinorSubsystemVersion','SizeOfHeaders','CheckSum','SizeOfImage','Subsystem','DllCharacteristics',
            'SizeOfStackReserve','SizeOfStackCommit','SizeOfHeapReserve','SizeOfHeapCommit','LoaderFlags','NumberOfRvaAndSizes','SuspiciousImportFunctions',
            'SuspiciousNameSection','SectionsLength','SectionMinEntropy','SectionMaxEntropy','SectionMinRawsize','SectionMaxRawsize','SectionMinVirtualsize',
            'SectionMaxVirtualsize','SectionMaxPhysical','SectionMinPhysical','SectionMaxVirtual','SectionMinVirtual','SectionMaxPointerData','SectionMinPointerData',
            'SectionMaxChar','SectionMainChar','DirectoryEntryImport','DirectoryEntryImportSize','DirectoryEntryExport','ImageDirectoryEntryExport','ImageDirectoryEntryImport',
            'ImageDirectoryEntryResource','ImageDirectoryEntryException','ImageDirectoryEntrySecurity']  # 생략 (기존 코드와 동일하게 유지)
x = dropped_df
y = df['Malware']

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
x_scaled = scaler.fit_transform(x_train)
x_new = pd.DataFrame(x_scaled, columns=x.columns)

skpca = PCA(n_components =  55)
x_pca = skpca.fit_transform(x_new)
print('Variance sum : ', skpca.explained_variance_.cumsum()[-1])

# ✅ LightGBM 모델로 교체
model = LGBMClassifier(
    n_estimators=100,
    max_depth=16,
    random_state=0,
    n_jobs=-1
)

model.fit(x_pca, y_train)

x_test_scaled = scaler.transform(x_test)
x_new_test = pd.DataFrame(x_test_scaled, columns=x.columns)
x_test_pca = skpca.transform(x_new_test)

y_pred = model.predict(x_test_pca)
print(classification_report(y_pred, y_test))

pipe = Pipeline([('scale', scaler), ('pca', skpca), ('clf', model)])
x_testing = df1.drop('Name', axis=1)

x_testing_scaled = pipe.named_steps['scale'].transform(x_testing)
x_testing_pca = pipe.named_steps['pca'].transform(x_testing_scaled)
y_testing_pred = pipe.named_steps['clf'].predict_proba(x_testing_pca)
print(pd.concat([df1['Name'], pd.DataFrame(y_testing_pred)], axis = 1))

y_test_proba = model.predict_proba(x_test_pca)[:, 1]

precision, recall, thresholds = precision_recall_curve(y_test, y_test_proba)
f1_scores = 2 * (precision * recall) / (precision + recall + 1e-8)
best_threshold = thresholds[np.argmax(f1_scores)]
print(f"✅ 자동 튜닝된 최적 threshold: {best_threshold:.4f}")

y_proba = y_testing_pred[:, 1]
malware_pred = (y_proba > best_threshold)

malicious_df = df1[malware_pred].copy()
malicious_df['Probability'] = y_proba[malware_pred]
malicious_df['PredictedMalware'] = 1

save_columns = ['Name', 'Probability', 'PredictedMalware']
if 'FullPath' in malicious_df.columns:
    save_columns.append('FullPath')

malicious_df.to_csv('./detected_malwares.csv', columns=save_columns, index=False)
print(f"📁 {malicious_df.shape[0]}개 악성코드 저장 완료 (자동 threshold 적용)")
