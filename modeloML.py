import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

raw_dataset = pd.read_csv('webpage_phishing_detection_dataset.csv')
raw_dataset.head()
raw_dataset.shape
raw_dataset.describe()
pd.set_option('display.max_rows', 500)
raw_dataset.isna().sum()
pd.reset_option('display.max_rows')
original_dataset = raw_dataset.copy()
class_map = {'legitimate':0, 'phishing':1}
original_dataset['status'] = original_dataset['status'].map(class_map)
corr_matrix = original_dataset.corr()
plt.figure(figsize=(60,60))
color = plt.get_cmap('viridis').copy()   # default color
color.set_bad('lightblue') 
sns.heatmap(corr_matrix, annot=True, linewidth=0.4, cmap=color)
plt.savefig('heatmap')
plt.show()
corr_matrix.shape
corr_matrix['status']
status_corr = corr_matrix['status']
status_corr.shape

def feature_selector_correlation(cmatrix, threshold):
    
    selected_features = []
    feature_score = []
    i=0
    for score in cmatrix:
        if abs(score)>threshold:
            selected_features.append(cmatrix.index[i])
            feature_score.append( ['{:3f}'.format(score)])
        i+=1
    result = list(zip(selected_features,feature_score)) 
    return result

features_selected = feature_selector_correlation(status_corr, 0.2)
features_selected

selected_features = [i for (i,j) in features_selected if i != 'status']
selected_features

X_selected = original_dataset[selected_features]
X_selected

X_selected.shape

y = original_dataset['status']
y

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X_selected, y,
                                                    test_size=0.2,
                                                    random_state=42,
                                                    shuffle = True)

model_random_forest = RandomForestClassifier(n_estimators=350,
                                             random_state=42,
                                            )

model_random_forest.fit(X_train,y_train)

from sklearn import preprocessing
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score

def custom_accuracy_set (model, X_train, X_test, y_train, y_test, train=True):
    
    lb = preprocessing.LabelBinarizer()
    lb.fit(y_train)
    
    
    if train:
        x = X_train
        y = y_train
    elif not train:
        x = X_test
        y = y_test
        
    y_predicted = model.predict(x)
    
    accuracy = accuracy_score(y, y_predicted)
    print('model accuracy: {0:4f}'.format(accuracy))
    oconfusion_matrix = confusion_matrix(y, y_predicted)
    print('Confusion matrix: \n {}'.format(oconfusion_matrix))
    oroc_auc_score = lb.transform(y), lb.transform(y_predicted)
    custom_accuracy_set(model_random_forest, X_train, X_test, y_train, y_test, train=True)
    custom_accuracy_set(model_random_forest, X_train, X_test, y_train, y_test, train=False)

import pickle

with open('model_phishing_webpage_classifer','wb') as file:
    pickle.dump(model_random_forest,file)