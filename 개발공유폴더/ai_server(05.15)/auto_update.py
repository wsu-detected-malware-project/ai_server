import time
from ai_model.trainer import training as train_models

INTERVAL_HOURS = 6  # 주기 시간 (6시간)

def run_scheduler():
    while True:
        print("자동 재학습 시작.")
        try:
            train_models()
            print("모델 재학습 완료.")
        except Exception as e:
            print(f"재학습 중 오류 발생: {e}")

        print("다음 재학습까지 대기: {}시간\n".format(INTERVAL_HOURS))
        time.sleep(INTERVAL_HOURS * 60 * 60)