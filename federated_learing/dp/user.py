from opacus import PrivacyEngine
import torch
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm
import numpy as np


# Step 2: Loading MNIST Data
train_loader = torch.utils.data.DataLoader(datasets.MNIST('../mnist', train=True, download=True,
               transform=transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.1307,), 
               (0.3081,)),]),), batch_size=64, shuffle=True, num_workers=1, pin_memory=True)

test_loader = torch.utils.data.DataLoader(datasets.MNIST('../mnist', train=False, 
              transform=transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.1307,), 
              (0.3081,)),]),), batch_size=1024, shuffle=True, num_workers=1, pin_memory=True)


# Step 3: Creating a PyTorch Neural Network Classification Model and Optimizer
model = torch.nn.Sequential(torch.nn.Conv2d(1, 16, 8, 2, padding=3), torch.nn.ReLU(), torch.nn.MaxPool2d(2, 1),
        torch.nn.Conv2d(16, 32, 4, 2),  torch.nn.ReLU(), torch.nn.MaxPool2d(2, 1), torch.nn.Flatten(), 
        torch.nn.Linear(32 * 4 * 4, 32), torch.nn.ReLU(), torch.nn.Linear(32, 10))

optimizer = torch.optim.SGD(model.parameters(), lr=0.05)

# Step 4: Attaching a Differential Privacy Engine to the Optimizer
privacy_engine = PrivacyEngine()
model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=train_loader,
    target_epsilon=8.0,
    target_delta=1e-5,
    epochs=1, 
    max_grad_norm=1.0,
)

# privacy_engine = PrivacyEngine(model, batch_size=64, sample_size=60000, alphas=range(2,32), 
#                                noise_multiplier=1.3, max_grad_norm=1.0,)

# privacy_engine.attach(optimizer)

# Step 5: Training the private model over multiple epochs
def train(model, train_loader, optimizer, epoch, device, delta):
    model.train()
    criterion = torch.nn.CrossEntropyLoss()
    # losses = []    
    for _batch_idx, (data, target) in enumerate(tqdm(train_loader)):
        data, target = data.to(device), target.to(device)
        optimizer.zero_grad()
        output = model(data)
        loss = criterion(output, target)
        loss.backward()
        optimizer.step()
    #     losses.append(loss.item())    
    # epsilon, best_alpha = optimizer.privacy_engine.get_privacy_spent(delta) 
    # print(
    #     f"Train Epoch: {epoch} \t"
    #     f"Loss: {np.mean(losses):.6f} "
    #     f"(ε = {epsilon:.2f}, δ = {delta}) for α = {best_alpha}")

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)


# for epoch in range(1, 11):
#     train(model, train_loader, optimizer, epoch, device, delta=1e-5)
train(model, train_loader, optimizer, 1, device, delta=1e-5)


print(type(model.named_parameters()))

def get_gradients(model):
    """
    提取模型的梯度（客户端更新向量），即在单次训练迭代后的模型参数梯度。
    """
    gradients = {name: param.grad for name, param in model.named_parameters()}
    # for name, param in model.named_parameters():
    #     print(name)
    #     print(param.grad.clone())
    #     print(param.grad.clone().shape)
    #     break
    return gradients

# 假设是在某个训练迭代后调用此函数
client_update_vector1 = get_gradients(model)
# print(client_update_vector)
# print(client_update_vector[0].keys())

train(model, train_loader, optimizer, 1, device, delta=1e-5)
client_update_vector2 = get_gradients(model)

client_update_vector = [client_update_vector1, client_update_vector2]

# print(client_update_vector1)
# print(client_update_vector2)

# print(client_update_vector[0].keys())
# print(client_update_vector[1].keys())


# server-side

def aggregate_gradients(client_gradients):
    aggregated_gradients = {}
    for key in client_gradients[0].keys():
        aggregated_gradients[key] = torch.mean(
            torch.stack([grads[key] for grads in client_gradients]), dim=0
        )
    return aggregated_gradients

avg_vector = aggregate_gradients(client_update_vector)

print(avg_vector)


def update_model_gradients(model, aggregated_updates):
    for name, param in model.named_parameters():
        if name in aggregated_updates:
            print(name)
            if param.grad is None:
                param.grad = aggregated_updates[name]
            else:
                param.grad.data.copy_(aggregated_updates[name])

def update_model_parameters(model, lr=0.05):
    for name, param in model.named_parameters():
        # param.data.copy_(param.data - lr * param.grad)
        param.data -= lr * param.grad

def get_parameters(model):
    params = {name: param for name, param in model.named_parameters()}
    # for name, param in model.named_parameters():
    #     print(name)
    #     print(param.grad.clone())
    #     print(param.grad.clone().shape)
    #     break
    return params

# 假设 aggregated_updates 是从服务器接收到的聚合后的更新向量
# model 是客户端的模型实例
# print()
print(get_parameters(model))
update_model_gradients(model, avg_vector)
update_model_parameters(model)
print(get_parameters(model))

# optimizer.step()