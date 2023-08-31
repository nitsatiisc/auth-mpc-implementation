from sklearn import datasets
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
#data = datasets.load_breast_cancer()
#print(data)
#print(data.shape)

#df = pd.DataFrame(data=data['data'])
#df = df.multiply(10000).astype("int")
#print(df)

n_features = 4
n_stats = 6
n_samples = 400
n_parties = 5

pub_data = np.random.random_integers(1, 4, (n_parties, n_samples, n_features))
priv_data = np.random.normal(50, 10, (n_parties, n_samples, n_stats))

#print(pub_data)
#print(priv_data)

full_data_0 = np.concatenate((pub_data[0], priv_data[0]), axis=1)
full_data_1 = np.concatenate((pub_data[1], priv_data[1]), axis=1)
full_data_2 = np.concatenate((pub_data[2], priv_data[2]), axis=1)
full_data_3 = np.concatenate((pub_data[3], priv_data[3]), axis=1)
full_data_4 = np.concatenate((pub_data[4], priv_data[4]), axis=1)
# full_data_2 = np.concatenate((pub_data[2], priv_data[2]), axis=1)

df_features_0 = pd.DataFrame(full_data_0).astype('int')
df_features_1 = pd.DataFrame(full_data_1).astype('int')
df_features_2 = pd.DataFrame(full_data_2).astype('int')
df_features_3 = pd.DataFrame(full_data_3).astype('int')
df_features_4 = pd.DataFrame(full_data_4).astype('int')
#df_features_2 = pd.DataFrame(full_data_2).astype('int')

#df_stats_0 = pd.DataFrame(priv_data[0]).astype('int')
#df_stats_1 = pd.DataFrame(priv_data[1]).astype('int')
#df_stats_2 = pd.DataFrame(priv_data[2]).astype('int')

df_features_0.to_csv('./data/Input-P0-0', sep=' ', header=False, index=False)
df_features_1.to_csv('./data/Input-P1-0', sep=' ', header=False, index=False)
df_features_2.to_csv('./data/Input-P2-0', sep=' ', header=False, index=False)
df_features_3.to_csv('./data/Input-P3-0', sep=' ', header=False, index=False)
df_features_4.to_csv('./data/Input-P4-0', sep=' ', header=False, index=False)
#df_features_2.to_csv('./data/Input-P2-0', sep=' ', header=False, index=False)

#df_stats_0.to_csv('./data/Input-P0-0', sep=' ', header=False, index=False, mode='a')
#df_stats_1.to_csv('./data/Input-P1-0', sep=' ', header=False, index=False, mode='a')
#df_stats_2.to_csv('./data/Input-P2-0', sep=' ', header=False, index=False, mode='a')










'''
df1 = df.iloc[0:100]
df2 = df[100:200]
df3 = df[200:300]

df1.to_csv('./data/Input-P0-0', sep = ' ', header = False, index = False)
df2.to_csv('./data/Input-P1-0', sep = ' ', header = False, index = False)
df3.to_csv('./data/Input-P2-0', sep = ' ', header = False, index = False)

df = pd.DataFrame(data=data['target'])
df = df.astype('int')
df1 = df.iloc[0:100]
df2 = df[100:200]
df3 = df[200:300]

df1.to_csv('./data/Input-P0-0', sep = ' ', header = False, index = False, mode='a')
df2.to_csv('./data/Input-P1-0', sep = ' ', header = False, index = False, mode='a')
df3.to_csv('./data/Input-P2-0', sep = ' ', header = False, index = False, mode='a')

#df.to_csv('./data/breast_cancer.csv', sep = ' ', index = False)

#df = pd.DataFrame(data['target'])
#df.to_csv('./data/breast_cancer_labels.csv', sep = '\n', index  = False);
'''