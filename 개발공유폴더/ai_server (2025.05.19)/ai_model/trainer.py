import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report
from lightgbm import LGBMClassifier
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
import db.db_control as db
from db.db_login import engine

def train_and_save_model(model, model_name, x_train, y_train, x_test, y_test, pipeline, save_dir='./models'):
    x_train_prep = pipeline.fit_transform(x_train)
    x_test_prep = pipeline.transform(x_test)

    model.fit(x_train_prep, y_train)

    # 성능 출력
    y_pred = model.predict(x_test_prep)
    print(f'------------------ {model_name} ------------------')
    print(classification_report(y_test, y_pred))

    os.makedirs(save_dir, exist_ok=True)
    temp_path = os.path.join(save_dir, f'{model_name}_model_temp.pkl')
    final_path = os.path.join(save_dir, f'{model_name}_model.pkl')

    # 임시 파일로 저장
    joblib.dump((pipeline, model), temp_path)

    # 락을 걸고 원자적으로 교체
    from filelock import FileLock
    with FileLock(final_path + '.lock'):
        os.replace(temp_path, final_path)

def training():
    # DB에서 데이터 불러오기
    query = db.search()
    df = pd.read_sql(query, engine)

    x = df.drop(['Name', 'Malware'], axis=1)
    y = df['Malware'].astype(str).astype(int)

    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.2, random_state=42, stratify=y
    )

    # 공통 파이프라인
    pipeline = Pipeline([
        ('scale', StandardScaler()),
        ('pca', PCA(n_components=55))
    ])

    train_and_save_model(LGBMClassifier(n_estimators=100, max_depth=16, random_state=0, n_jobs=-1), 'lgvm', x_train, y_train, x_test, y_test, pipeline)
    train_and_save_model(RandomForestClassifier(n_estimators=100, max_depth=16, oob_score=True, random_state=0), 'random_forest', x_train, y_train, x_test, y_test, pipeline)
    train_and_save_model(SVC(kernel='rbf', C=1.0, gamma='scale', probability=True, random_state=42), 'svm', x_train, y_train, x_test, y_test, pipeline)
    train_and_save_model(XGBClassifier(n_estimators=100, random_state=42, max_depth=16, objective='binary:logistic', eval_metric='logloss'), 'xgboost', x_train, y_train, x_test, y_test, pipeline)