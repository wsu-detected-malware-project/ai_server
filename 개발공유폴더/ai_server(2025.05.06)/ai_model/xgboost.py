import joblib
import pandas as pd
from filelock import FileLock
import warnings
warnings.simplefilter('ignore')

def xgboost(file):
    df1 = pd.read_csv(file)
    model_path = './models/xgboost_model.pkl'

    with FileLock(model_path + '.lock'):
        pipeline, model = joblib.load(model_path)

    x_testing = df1.drop(['Name'], axis=1)
    x_testing_scaled = pipeline.named_steps['scale'].transform(x_testing)
    x_testing_pca = pipeline.named_steps['pca'].transform(x_testing_scaled)
    y_testing_pred = model.predict_proba(x_testing_pca)

    result = pd.concat([df1['Name'], pd.DataFrame(y_testing_pred)], axis=1)
    print(result)
    result.to_csv('ai4_result.csv', index=False)

    return y_testing_pred
