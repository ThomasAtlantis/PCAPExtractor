import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from model import Network
import os

# Use fixed random seed
np.random.seed(1)
torch.manual_seed(1)

# Define model parameters
epoch, batch_size = 30, 32
learning_rate = 0.01
input_size, output_size = 256, 3

# Load dataset
data_path = "/home/lsy/workspace/traffic/"
train_X, train_y = np.load(os.path.join(data_path, 'data_X.npy')), np.load(os.path.join(data_path, 'data_y.npy'))
train_data = TensorDataset(torch.Tensor(train_X).squeeze(-1), F.one_hot(torch.LongTensor(train_y), output_size).float())
train_loader = DataLoader(dataset=train_data, batch_size=batch_size, shuffle=True)
train_file = None

# Instantiate the model
model = Network(input_size, output_size)


# Optimizer
optimizer = torch.optim.Adam(model.parameters())

# Loss function
loss_func = nn.CrossEntropyLoss()

# Training loop
for i in range(epoch):
    loss_value = 0
    prec_value = 0
    counter = 0
    for X, y in train_loader:
        output = model(X)
        loss = loss_func(output, y)
        prec = (torch.max(output, -1)[1] == torch.max(y, -1)[1]).float().mean()

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        loss_value += loss.item()
        prec_value += prec.item()
        counter += 1

    loss_value /= counter
    prec_value /= counter
    print(f"Epoch {i}: loss={loss_value:.6f} acc={prec_value:.6f}")
torch.save(model, r"C:\Users\lwx1111017\Desktop\FLWork\model.pth")
