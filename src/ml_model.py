import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, confusion_matrix

class MLModel():
    def __init__(self, norm_network_flow_stream, mal_network_flow_stream):
        self.norm_network_flow_stream = norm_network_flow_stream
        self.mal_network_flow_stream = mal_network_flow_stream
        self.X_train = None
        self.tree_model = None
        self.accuracy = None
        self.conf_matrix = None
        self.recall = None
        self.precision = None
        self._train_model()

    def _prepare_data(self):
        # Requirement ML.1
        normal_flows = self.norm_network_flow_stream.to_pandas()
        normal_flows["label"] = 0
        
        malicious_flows = self.mal_network_flow_stream.to_pandas()
        malicious_flows["label"] = 1
       
        data = pd.concat([normal_flows, malicious_flows], ignore_index=True)
        for col in data.columns:
            if data[col].nunique() == 1 or data[col].isnull().any():
                data.drop(columns=[col], inplace=True, axis=1)

        data = data.select_dtypes(include=[np.number])
        
        X = data.drop(columns=["label"], axis=1)
        Y = data["label"]

        X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.4, random_state=42)
        return X_train, X_test, Y_train, Y_test
    
    def _train_model(self, max_depth=3, criterion="gini", min_samples_split=5, min_samples_leaf=2):
        # Requirement ML.1 + ML.2
        X_train, X_test, Y_train, Y_test = self._prepare_data()
    
        tree_model = DecisionTreeClassifier(
            max_depth=max_depth,  
            criterion=criterion,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            random_state=42,
            ccp_alpha=0.01
        )
        tree_model.fit(X_train, Y_train)
        
        
        predictions = tree_model.predict(X_test)
        self.accuracy = accuracy_score(Y_test, predictions)
        print("Accuracy: ", self.accuracy)
        self.conf_matrix = confusion_matrix(Y_test, predictions)
        self.recall = self.conf_matrix[1][1] / (self.conf_matrix[1][0] + self.conf_matrix[1][1])
        self.precision = self.conf_matrix[1][1] / (self.conf_matrix[0][1] + self.conf_matrix[1][1])
        self.tree_model = tree_model
        self.X_train = X_train