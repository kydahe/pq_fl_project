def aggregate_updates(client_updates):
    """
    聚合客户端的更新向量。
    client_updates: 客户端发送的更新向量的列表，每个元素是一个客户端的模型参数字典。
    """
    # 初始化聚合的更新向量
    aggregated_updates = {k: torch.zeros_like(v) for k, v in client_updates[0].items()}
    
    # 将所有客户端的更新相加
    for update in client_updates:
        for k, v in update.items():
            aggregated_updates[k] += v
    
    # 求平均
    for k in aggregated_updates:
        aggregated_updates[k] = aggregated_updates[k] / len(client_updates)
    
    return aggregated_updates

# 假设client_updates是从客户端收集到的更新向量列表
# aggregated_updates = aggregate_updates(client_updates)

# 更新全局模型参数
# for name, param in global_model.named_parameters():
#    param.data += aggregated_updates[name]
