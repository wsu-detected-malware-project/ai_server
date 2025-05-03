import pandas as pd

def avg(time):

    df = pd.read_csv(f'./ai1_result_{time}.csv').drop_duplicates(subset='Name')
    df1 = pd.read_csv(f'./ai2_result_{time}.csv').drop_duplicates(subset='Name')
    df2 = pd.read_csv(f'./ai3_result_{time}.csv').drop_duplicates(subset='Name')
    df3 = pd.read_csv(f'./ai4_result_{time}.csv').drop_duplicates(subset='Name')

    # 'Name' 열 기준으로 병합하면서 0, 1 열 값 더하기
    merged = pd.merge(df, df1, on='Name', suffixes=('_a', '_b'))
    merged['0'] = merged['0_a'] + merged['0_b']
    merged['1'] = merged['1_a'] + merged['1_b']
    merged = merged[['Name', '0', '1']]

    merged = pd.merge(merged, df2, on='Name', suffixes=('', '_c'))
    merged['0'] = merged['0'] + merged['0_c']
    merged['1'] = merged['1'] + merged['1_c']
    merged = merged[['Name', '0', '1']]

    merged = pd.merge(merged, df3, on='Name', suffixes=('', '_d'))
    merged['0'] = (merged['0'] + merged['0_d'])/4
    merged['1'] = (merged['1'] + merged['1_d'])/4
    merged = merged[['Name', '0', '1']]

    merged.to_csv(f'avg_result_{time}.csv', index=False)

    return merged