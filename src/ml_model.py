import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from nfstream import NFPlugin, NFStreamer

class ModelPrediction(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.ml_prediction = 0

    def on_expire(self, flow):
        numerical_features = [
            flow.bidirectional_packets,
            flow.bidirectional_bytes,
            flow.src2dst_packets,
            flow.src2dst_bytes,
            flow.dst2src_packets, 
            flow.dst2src_bytes,
            flow.bidirectional_duration_ms,
            flow.src2dst_duration_ms,
            flow.dst2src_duration_ms,
            flow.src_port,
            flow.dst_port,
            flow.protocol
        ]
    
        to_predict = np.array(numerical_features).reshape(1, -1)
        flow.udps.model_prediction = self.my_model.predict(to_predict)[0]
    

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
       
        selected_columns = [
        'bidirectional_packets',
        'bidirectional_bytes',
        'src2dst_packets',
        'src2dst_bytes',
        'dst2src_packets',
        'dst2src_bytes',
        'bidirectional_duration_ms',
        'src2dst_duration_ms',
        'dst2src_duration_ms',
        'src_port',
        'dst_port',
        'protocol',
        'label'
        ]
    
        data = pd.concat([normal_flows, malicious_flows], ignore_index=True)
        data = data[selected_columns]

        X = data.drop(columns=["label"], axis=1)
        Y = data["label"]

        X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42, stratify=Y)
        return X_train, X_test, Y_train, Y_test
    

    def retrain_model(self, normal_stream, malicious_stream):
        # Requirement ML.3
        norm_network_flow_stream = NFStreamer(source=normal_stream, statistical_analysis=True)
        mal_network_flow_stream = NFStreamer(source=malicious_stream, statistical_analysis=True)
        self.norm_network_flow_stream = norm_network_flow_stream
        self.mal_network_flow_stream = mal_network_flow_stream
        self._train_model()



    def _train_model(self, max_depth=3, criterion="gini", min_samples_split=5, min_samples_leaf=2):
        # Requirement ML.1 + ML.2
        X_train, X_test, Y_train, Y_test = self._prepare_data()
        if self.tree_model is None:
            tree_model = DecisionTreeClassifier(
                max_depth=max_depth,  
                criterion=criterion,
                min_samples_split=min_samples_split,
                min_samples_leaf=min_samples_leaf,
                random_state=42,
                ccp_alpha=0.01
            )
            tree_model.fit(X_train.values, Y_train)
        else:
            tree_model = self.tree_model
            tree_model.fit(X_train.values, Y_train)
        
        
        predictions = tree_model.predict(X_test.values)
        self.accuracy = accuracy_score(Y_test, predictions)
        self.conf_matrix = confusion_matrix(Y_test, predictions)
        self.recall = self.conf_matrix[1][1] / (self.conf_matrix[1][0] + self.conf_matrix[1][1])
        self.precision = self.conf_matrix[1][1] / (self.conf_matrix[0][1] + self.conf_matrix[1][1])
        self.tree_model = tree_model
        self.X_train = X_train

