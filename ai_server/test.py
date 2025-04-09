import pandas as pd

df = pd.read_csv('./avg_result.csv')

filtered_df = df[df['1']>0.5]

filtered_df.to_csv('result.csv',index=False)