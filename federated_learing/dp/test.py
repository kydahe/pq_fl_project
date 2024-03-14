from opacus import PrivacyEngine
import torch
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm
import numpy as np


def get_gradients(model):
    gradients = {name: param.grad for name, param in model.named_parameters()}
    # for name, param in model.named_parameters():
    #     print(name)
    #     print(param.grad.clone())
    #     print(param.grad.clone().shape)
    #     break
    return gradients

def gradients_to_np_array(gradients):
    mid_gradients = {}
    flat_gradients = []
    for name, grad in gradients.items():
        grad = grad.cpu()
        flat_grad = torch.flatten(grad)
        grad_np = flat_grad.numpy()
        mid_gradients[name] = grad_np
    flat_gradients = np.concatenate([arr for arr in mid_gradients.values()])
    return flat_gradients, mid_gradients


def get_shape(model, gradients):
    original_shapes = {}
    for name, param in model.named_parameters():
        original_shapes[name] = [param.grad.shape, len(gradients[name])]
    return original_shapes

def np_array_to_gradients(flat_gradients, original_shapes, device='cuda:0'):
    gradients = {}
    i = 0
    for name in original_shapes:
        original_shape = original_shapes[name][0]
        shape_len = original_shapes[name][1]
        grad_np = flat_gradients[i: i+shape_len]
        param_grad_flat = torch.from_numpy(grad_np)
        param_grad = param_grad_flat.reshape(original_shape)
        gradients[name] = param_grad.to(device)
        i = i+shape_len
    return gradients

# def gradients_to_np_array(gradients):
#     flat_gradients = torch.cat([grad.flatten() for grad in gradients])
#     grad_np = flat_gradients.numpy()
#     return grad_np

# def np_array_to_gradients(grad_np, model):
#     gradients = []
#     index = 0
#     for param in model.parameters():
#         param_grad = grad_np[index:index + param.numel()].reshape(param.shape)
#         gradients.append(param_grad)
#         index += param.numel()
#     return gradients

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




# server-side

def aggregate_gradients(client_gradients):
    aggregated_gradients = {}
    for key in client_gradients[0].keys():
        aggregated_gradients[key] = torch.mean(
            torch.stack([grads[key] for grads in client_gradients]), dim=0
        )
    return aggregated_gradients



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
    return params

def compare_tensor_dicts(dict1, dict2):
    # check keys
    if dict1.keys() != dict2.keys():
        return False
    
    # check values
    for key in dict1:
        if not torch.equal(dict1[key], dict2[key]):
            return False
    
    return True


# Loading MNIST Data
train_loader = torch.utils.data.DataLoader(datasets.MNIST('../mnist', train=True, download=True,
               transform=transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.1307,), 
               (0.3081,)),]),), batch_size=64, shuffle=True, num_workers=1, pin_memory=True)

test_loader = torch.utils.data.DataLoader(datasets.MNIST('../mnist', train=False, 
              transform=transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.1307,), 
              (0.3081,)),]),), batch_size=1024, shuffle=True, num_workers=1, pin_memory=True)


# Creating a PyTorch Neural Network Classification Model and Optimizer
model = torch.nn.Sequential(torch.nn.Conv2d(1, 16, 8, 2, padding=3), torch.nn.ReLU(), torch.nn.MaxPool2d(2, 1),
        torch.nn.Conv2d(16, 32, 4, 2),  torch.nn.ReLU(), torch.nn.MaxPool2d(2, 1), torch.nn.Flatten(), 
        torch.nn.Linear(32 * 4 * 4, 32), torch.nn.ReLU(), torch.nn.Linear(32, 10))

optimizer = torch.optim.SGD(model.parameters(), lr=0.05)

# Attaching a Differential Privacy Engine to the Optimizer
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


device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

print("cuda" if torch.cuda.is_available() else "cpu")

train(model, train_loader, optimizer, 1, device, delta=1e-5)

print(type(model.named_parameters()))

client_update_vector1 = get_gradients(model)

flat_gradients, mid_gradients = gradients_to_np_array(client_update_vector1)

original_shapes = get_shape(model, mid_gradients)

restored_gradients = np_array_to_gradients(flat_gradients, original_shapes, device)

print(client_update_vector1)
print(restored_gradients)
print(flat_gradients)
print(original_shapes)
print(len(flat_gradients))
print(restored_gradients['_module.0.weight'].device)
print(client_update_vector1['_module.0.weight'].device)
print(compare_tensor_dicts(restored_gradients, client_update_vector1))

# print(restored_gradients==client_update_vector1)

# print(flat_gradients.shape)
# print(restored_gradients.shape)

# print(client_update_vector1.shape)



# train(model, train_loader, optimizer, 1, device, delta=1e-5)
# client_update_vector2 = get_gradients(model)

# client_update_vector = [client_update_vector1, client_update_vector2]


# avg_vector = aggregate_gradients(client_update_vector)

# print(avg_vector)


# # print()
# print(get_parameters(model))
# update_model_gradients(model, avg_vector)
# update_model_parameters(model)
# print(get_parameters(model))

# # optimizer.step()