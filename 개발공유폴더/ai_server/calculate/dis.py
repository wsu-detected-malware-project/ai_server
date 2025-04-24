import pandas as pd

def dis(time):
    df = pd.read_csv(f'./avg_result_{time}.csv')

    filtered_df = df[df['1']>0.5]

    filtered_df.to_csv(f'result_{time}.csv',index=False)

    return filtered_df
