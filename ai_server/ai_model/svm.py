import pandas as pd
from sklearn.svm import SVC  
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import warnings
warnings.simplefilter('ignore')

def svm(file, time):
    df = pd.read_csv('./dataset/dataset_malwares1.csv')
    df1 = pd.read_csv(file)

    dropped_df = df.drop(['Name','Malware'], axis=1)

    x = dropped_df
    y = df['Malware']

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x_train)
    x_new = pd.DataFrame(x_scaled, columns=x.columns)

    skpca = PCA(n_components=55)
    x_pca = skpca.fit_transform(x_new)

    model = SVC(
        kernel='rbf',  
        C=1.0,         
        gamma='scale', 
        probability=True, 
        random_state=42
    )

    model.fit(x_pca, y_train)

    x_test_scaled = scaler.transform(x_test)
    x_new_test = pd.DataFrame(x_test_scaled, columns=x.columns)
    x_test_pca = skpca.transform(x_new_test)

    y_pred = model.predict(x_test_pca)

    print('--------------------------svm----------------------------------')
    print(classification_report(y_pred, y_test))

    pipe = Pipeline([('scale', scaler), ('pca', skpca), ('clf', model)])
    x_testing = df1.drop('Name', axis=1)

    x_testing_scaled = pipe.named_steps['scale'].transform(x_testing)
    x_testing_pca = pipe.named_steps['pca'].transform(x_testing_scaled)
    y_testing_pred = pipe.named_steps['clf'].predict_proba(x_testing_pca)

    result = pd.concat([df1['Name'], pd.DataFrame(y_testing_pred)], axis=1)
    print(result)
    result.to_csv(f'./ai3_result_{time}.csv', index=False)

    return result