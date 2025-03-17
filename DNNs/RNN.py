import tensorflow as tf
import pandas as pd
import numpy as np
import os
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, GRU, Dense, Dropout, Concatenate, GlobalAveragePooling1D, Masking, Dot, Softmax
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.losses import CategoricalCrossentropy
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.metrics import classification_report
import re
import gensim.downloader as api

"""
DNN for our IDS. The DNN has two main branches:
1. A static branch that processes high-level request metadata
2. A sequential branch that processes packet-level sequences - This is the part that contains our GDB augmentation

A custom tokenizer is also implemented to process textual information from packet caps and GDB
Tokens are mapped to FastText embeddings, averaged to form a fixed-length vector, and concatenated with other packet-level features.

Preprocessing for both static and sequential data is performed, and a tf.data pipeline is used to optimize training
The network is compiled using Adam optimiser and categorical cross-entropy loss, with using accuracy, precision, recall, and F1 score as eval metrics
"""

# --- Data Loader Class: RequestSequenceLoader ---
class RequestSequenceLoader:
    def __init__(self, static_csv, sequential_csv, batch_size=32, request_ids=None,
                 num_scaler=None, cat_encoder=None, proto_encoder=None,
                 class_names=None, embedding_model_name="fasttext-wiki-news-subwords-300", embedding_dim=300):

        self.main_csv_path = static_csv
        self.combined_packets_path = sequential_csv
        self.batch_size = batch_size
        self.request_ids = request_ids

        #Load the high-level metadata (static features)
        self.main_df = pd.read_csv(static_csv)
        print(f"Initial main_df shape: {self.main_df.shape}")

        #Load the packet-level CSV and group packets by request_id
        self.combined_packets = pd.read_csv(sequential_csv)
        self.packet_groups = dict(tuple(self.combined_packets.groupby('request_id')))

        #Handle missing values in attack labels before extracting class names - This is an artefact left over from testing and will be removed
        print(f"Unique ' attack_cat' BEFORE handling missing: {self.main_df[' attack_cat'].unique()}")
        self.main_df[' attack_cat'] = self.main_df[' attack_cat'].fillna("Missing")
        self.main_df[' attack_cat'] = self.main_df[' attack_cat'].replace('', "Missing")
        self.main_df[' attack_cat'] = self.main_df[' attack_cat'].astype(str)
        print(f"Unique ' attack_cat' AFTER handling missing: {self.main_df[' attack_cat'].unique()}")

        #TEMPORARILY remove requests labeled as 'worms' (for testing) - This is an extremely underrepresented class, so we can use it for evaluating novel attack detection later
        self.main_df = self.main_df[self.main_df[' attack_cat'] != 'worms']
        print(f"main_df shape after removing 'worms': {self.main_df.shape}")

        #Initialise/store preprocessing objects
        self.num_scaler = num_scaler if num_scaler is not None else StandardScaler()
        self.cat_encoder = cat_encoder if cat_encoder is not None else OneHotEncoder(handle_unknown='ignore')
        self.proto_encoder = proto_encoder if proto_encoder is not None else OneHotEncoder(handle_unknown='ignore')

        #Get class names from the attack labels
        if class_names is None:
            self.class_names = sorted(self.main_df[' attack_cat'].unique().tolist())
        else:
            self.class_names = class_names

        self.n_classes = len(self.class_names)
        print(f"Initial class_names: {self.class_names}")
        print(f"Initial n_classes: {self.n_classes}")

        #Filter the main dataframe and packet groups by req id
        if request_ids is not None:
            print(f"Filtering request_ids: {request_ids[:10]} ... (first 10)")
            original_shape = self.main_df.shape
            self.main_df = self.main_df[self.main_df['request_id'].isin(request_ids)]
            print(f"main_df shape AFTER filtering: {self.main_df.shape}")
            print(f"Number of rows removed: {original_shape[0] - self.main_df.shape[0]}")
            valid_ids = set(request_ids) & set(self.packet_groups.keys())
            self.packet_groups = {k: v for k, v in self.packet_groups.items() if k in valid_ids}

        #Update req ids based on this filter
        self.request_ids = self.main_df['request_id'].unique()
        print(f"Final request_ids in __init__: {self.request_ids[:10]} ... (first 10)")
        print(f"Final n_classes in __init__: {self.n_classes}")

        #Load pre-trained FastText embedding model and create the custom tokenizer
        self.embedding_dim = embedding_dim
        self.embedding_model = self._load_embedding_model(embedding_model_name)
        self.tokenizer = self._create_tokenizer()

        #Calculate the maximum sequence length across request (for uniformity)
        self.global_max_len = self._get_global_max_sequence_length()

        if not hasattr(self.proto_encoder, "categories_"):
            self._get_all_protocols()

        #Scale and encode static features
        self._preprocess_static_features()

        #Set sequence feature dimension based on protocol encoding and embedding dimensions
        self.sequence_feature_dim = 2 + len(self.proto_encoder.categories_[0]) + self.embedding_dim

    def _load_embedding_model(self, model_name):
        #Loads a FastText embedding model
        try:
            return api.load(model_name)
        except ValueError:
            print(f"Embedding model '{model_name}' not found. Available models:")
            print(api.info()['models'].keys())
            raise

    def _create_tokenizer(self):
        #Creates a custom tokenizer for processing packet 'Info' strings and GDB output
        def tokenize(text):
            text = text.lower()  #Lowercase for uniformity
            # Keep hexadecimal addresses intact - Important for GDB
            text = re.sub(r'0x[0-9a-f]+', ' HEXADDR ', text)
            #Split text on common delimiters while preserving them
            tokens = re.findall(r'\b\w+\b|[/=:(),]', text)
            #Remove empty tokens
            tokens = [t for t in tokens if t.strip()]
            return tokens
        return tokenize

    def _process_info_string(self, info_string):
        #Converts an 'Info' string into a sequence of FastText embeddings
        tokens = self.tokenizer(info_string)
        embeddings = []
        for token in tokens:
            try:
                embeddings.append(self.embedding_model[token])
            except KeyError:
                #For tokens not found in the model, use a zero vector
                embeddings.append(np.zeros(self.embedding_dim))
        return np.array(embeddings)

    def _get_global_max_sequence_length(self):
        if not self.packet_groups:
            return 0
        max_len = max(len(df) for df in self.packet_groups.values())
        return min(max_len, 200)

    def _get_all_protocols(self):
        all_protocols = list(self.combined_packets['Protocol'].unique())
        self.proto_encoder.fit(np.array(all_protocols).reshape(-1, 1))

    def _preprocess_static_features(self):
        #Preprocesses static features by:
        #  - Dropping columns not used for static features
        #  - Scaling numerical features
        #  - One-hot encoding categorical features
        #The resulting static feature matrix is stored in self.static_features

        temp_df = self.main_df.drop(columns=['request_id', ' attack_cat', 'srcip', ' dstip', ' sport', ' dsport', ' Label'])
        temp_df.columns = temp_df.columns.str.strip()
        numerical_cols = temp_df.select_dtypes(include=['number']).columns
        if not hasattr(self.num_scaler, 'n_features_in_'):
            numerical_features = self.num_scaler.fit_transform(temp_df[numerical_cols])
        else:
            numerical_features = self.num_scaler.transform(temp_df[numerical_cols])
        categorical_cols = temp_df.select_dtypes(exclude=['number']).columns
        if not hasattr(self.cat_encoder, 'categories_'):
            categorical_features = self.cat_encoder.fit_transform(temp_df[categorical_cols]).toarray()
        else:
            categorical_features = self.cat_encoder.transform(temp_df[categorical_cols]).toarray()
        self.static_features = np.hstack([numerical_features, categorical_features])
        print(f"Static features shape: {self.static_features.shape}")

    def __len__(self):
        return int(np.ceil(len(self.request_ids) / self.batch_size))

    def __getitem__(self, idx, sample_ids=None):
        #Retrieves a batch of data based on the current index
        #Constructs paired inputs: static features and padded packet sequences, along with one-hot encoded labels
        batch_ids = self.request_ids[idx * self.batch_size : (idx + 1) * self.batch_size]
        batch_static = []
        batch_sequences = []
        batch_labels = []
        self.skipped_requests = 0  #Artefact from debugging - to be removed

        sample_ids = [] if sample_ids is None else (sample_ids.tolist() if not isinstance(sample_ids, list) else sample_ids)

        for req_id in batch_ids:
            if req_id in sample_ids:
                print(f"Debugging for {req_id}:")
            try:
                mask = self.main_df["request_id"] == req_id
                static_features = self.static_features[mask]
                if np.isnan(static_features).any():
                    static_features = np.nan_to_num(static_features)  #Replace NaNs with zeros
                packet_df = self.packet_groups.get(str(req_id), pd.DataFrame())
                if req_id in sample_ids:
                    print(f"Request ID: {req_id}, Number of packets loaded: {len(packet_df)}")
                if packet_df.empty:
                    sequence = np.zeros((1, self.sequence_feature_dim), dtype=np.float32)
                else:
                    #Extract time and length features from packet data
                    time_length = packet_df[["Time", "Length"]].values.astype(np.float32)
                    #One-hot encode protocol information
                    protocols = self.proto_encoder.transform(packet_df[["Protocol"]].values.reshape(-1, 1)).toarray().astype(np.float32)
                    #Process the 'Info' column to obtain embeddings
                    info_strings = packet_df['Info'].fillna("").astype(str)
                    all_embeddings = [self._process_info_string(info_str) for info_str in info_strings]
                    #Pad embeddings for uniform sequence lengths
                    padded_embeddings = tf.keras.preprocessing.sequence.pad_sequences(
                        all_embeddings, dtype='float32', padding='post', truncating='post'
                    )
                    #Average embeddings along the time dimension to form a fixed-length vector
                    average_embeddings = np.mean(padded_embeddings, axis=1)
                    if average_embeddings.ndim == 1:
                        average_embeddings = np.expand_dims(average_embeddings, axis=0)
                    #Concatenate time, protocol, and embedding features
                    sequence = np.hstack([time_length, protocols, average_embeddings])
                batch_static.append(static_features)
                batch_sequences.append(sequence)
                #One-hot encode the attack label
                label_str = self.main_df.loc[mask, ' attack_cat'].iloc[0]
                label_index = self.class_names.index(label_str)
                label_one_hot = np.zeros(self.n_classes, dtype=np.float32)
                label_one_hot[label_index] = 1.0
                batch_labels.append(label_one_hot)
            except Exception as e:
                print(f"Skipping request {req_id} due to error: {str(e)}")
                self.skipped_requests += 1
                continue

        if not batch_static:
            return ((np.empty((0, self.static_features.shape[1]), dtype=np.float32),
                     np.empty((0, self.global_max_len, self.sequence_feature_dim), dtype=np.float32)),
                    np.empty((0, self.n_classes), dtype=np.float32))

        padded_sequences = tf.keras.preprocessing.sequence.pad_sequences(
            batch_sequences, maxlen=self.global_max_len, dtype='float32', padding='post', truncating='post'
        )
        return ((np.array(batch_static, dtype=np.float32).reshape(-1, self.static_features.shape[1]),
                 padded_sequences),
                np.array(batch_labels, dtype=np.float32).reshape(-1, self.n_classes))

    def to_tf_dataset(self):
        #Converts the processed data into a tf.data.Dataset for batching, caching, and prefetching during training
        def generator():
            for i in range(len(self)):
                data = self[i]
                static_input, sequence_input = data[0]
                labels = data[1]
                if static_input.shape[0] == 0 or sequence_input.shape[0] == 0:
                    continue
                if static_input.ndim == 1:
                    static_input = static_input.reshape(1, -1)
                yield (tf.convert_to_tensor(static_input, dtype=tf.float32),
                       tf.convert_to_tensor(sequence_input, dtype=tf.float32)), \
                      tf.convert_to_tensor(labels, dtype=tf.float32)

        output_signature = (
            (tf.TensorSpec(shape=(None, self.static_features.shape[1]), dtype=tf.float32),
             tf.TensorSpec(shape=(None, self.global_max_len, self.sequence_feature_dim), dtype=tf.float32)),
            tf.TensorSpec(shape=(None, self.n_classes), dtype=tf.float32)
        )
        return tf.data.Dataset.from_generator(generator, output_signature=output_signature).cache().prefetch(tf.data.AUTOTUNE)

# --- Hybrid Model Architecture ---
def build_model(static_feature_dim, sequence_feature_dim, n_classes):
    #Constructs the RNN with our two branches:
    #The branches are merged and followed by dense layers to produce a final softmax output.

    #Static branch
    static_input = Input(shape=(static_feature_dim,))
    x = Dense(32, activation='relu')(static_input)
    x = Dropout(0.3)(x)

    #Sequential branch
    sequence_input = Input(shape=(None, sequence_feature_dim))
    mask = Masking(mask_value=0.0).compute_mask(sequence_input)
    y = GRU(64, return_sequences=True, recurrent_activation='sigmoid')(sequence_input, mask=mask)
    y = Dropout(0.4)(y)
    y = GRU(32, return_sequences=True, recurrent_activation='sigmoid')(y, mask=mask)
    y = Dropout(0.3)(y)

    #Attention mechanism: compute self-attention scores
    scores = Dot(axes=(2, 2))([y, y])
    attention_weights = Softmax()(scores)
    context_vector = Dot(axes=(2, 1))([attention_weights, y])
    attention_output = GlobalAveragePooling1D()(context_vector)

    #Merge static and sequential features
    combined = Concatenate()([x, attention_output])
    z = Dense(64, activation='relu')(combined)
    z = Dropout(0.2)(z)
    output = Dense(n_classes, activation='softmax')(z)

    return Model(inputs=[static_input, sequence_input], outputs=output)

# --- Training Setup ---
if __name__ == "__main__":
    #Initialise the full data loader with static and packet-level CSV files
    full_loader = RequestSequenceLoader(
        static_csv=r"#DATASETPATH",
        sequential_csv=r"#PACKETDATAPATH",
        batch_size=32
    )
    print(f"Full dataset - Classes: {full_loader.class_names}")
    print(f"Full dataset - Number of Classes: {full_loader.n_classes}")

    #Stratify the dataset based on attack category and split into training and test sets
    all_request_ids = full_loader.request_ids
    train_ids, test_ids = train_test_split(
        all_request_ids,
        test_size=0.2,
        random_state=42,
        stratify=full_loader.main_df[' attack_cat']
    )
    print(f"Train IDs (first 10): {train_ids[:10]}")
    print(f"Test IDs (first 10): {test_ids[:10]}")

    #Create training and test loaders
    train_loader = RequestSequenceLoader(
        static_csv=r"#DATASETPATH",
        sequential_csv=r"#PACKETDATAPATH",
        batch_size=32,
        request_ids=train_ids,
        num_scaler=full_loader.num_scaler,
        cat_encoder=full_loader.cat_encoder,
        proto_encoder=full_loader.proto_encoder,
        class_names=full_loader.class_names
    )
    print(f"Train Loader - Classes: {train_loader.class_names}")
    print(f"Train Loader - Number of Classes: {train_loader.n_classes}")

    test_loader = RequestSequenceLoader(
        static_csv=r"#DATASETPATH",
        sequential_csv=r"#PACKETDATAPATH",
        batch_size=32,
        request_ids=test_ids,
        num_scaler=full_loader.num_scaler,
        cat_encoder=full_loader.cat_encoder,
        proto_encoder=full_loader.proto_encoder,
        class_names=full_loader.class_names
    )
    print(f"Test Loader - Classes: {test_loader.class_names}")
    print(f"Test Loader - Number of Classes: {test_loader.n_classes}")

    #Convert the data loaders to TensorFlow datasets
    train_dataset = train_loader.to_tf_dataset()
    test_dataset = test_loader.to_tf_dataset()

    #Build the hybrid DNN model using dimensions from the full loader
    model = build_model(
        static_feature_dim=full_loader.static_features.shape[1],
        sequence_feature_dim=full_loader.sequence_feature_dim,
        n_classes=full_loader.n_classes
    )

    #Compile the model with Adam optimiser and categorical cross-entropy loss
    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss=CategoricalCrossentropy(),
        metrics=['accuracy',
                 tf.keras.metrics.Precision(name='precision'),
                 tf.keras.metrics.Recall(name='recall'),
                 tf.keras.metrics.F1Score(name='f1_score')]
    )

    #Train the model using the training dataset with validation on the test dataset, we can gather eval metrics properly later
    model.fit(
        train_dataset,
        epochs=10,
        validation_data=test_dataset
    )

    #Save the trained model
    model.save("unaugmentedDNN.keras")
