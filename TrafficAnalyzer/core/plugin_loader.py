import importlib
import pkgutil
import inspect
import os
import sys
import logging
from typing import List
from .strategy import BaseAnalyzer

logger = logging.getLogger(__name__)

def load_analyzers(analyzers_package: str, config: dict) -> List[BaseAnalyzer]:
    """
    动态加载指定包中的所有 BaseAnalyzer 子类。
    
    Args:
        analyzers_package: 包的点分路径 (例如 'TrafficAnalyzer.analyzers')
        config: 包含分析器配置的字典。键应匹配类名。
    """
    found_analyzers = []
    
    # 确保包可导入
    try:
        package = importlib.import_module(analyzers_package)
    except ImportError as e:
        logger.error(f"无法导入包 {analyzers_package}: {e}")
        return []

    # 遍历包目录
    if not hasattr(package, '__path__'):
        return []

    path = package.__path__
    prefix = package.__name__ + "."

    for _, name, ispkg in pkgutil.walk_packages(path, prefix):
        try:
            module = importlib.import_module(name)
            
            # 检查模块中的类
            for attribute_name in dir(module):
                attribute = getattr(module, attribute_name)
                
                if (inspect.isclass(attribute) and 
                    issubclass(attribute, BaseAnalyzer) and 
                    attribute is not BaseAnalyzer):
                    
                    # 避免重复加载 (简单检查: 检查是否已存在该类的实例)
                    if any(isinstance(a, attribute) for a in found_analyzers):
                        continue
                        
                    # 使用配置实例化
                    # 我们根据类名查找配置
                    class_name = attribute.__name__
                    analyzer_conf = config.get(class_name, {})
                    
                    try:
                        # 将配置作为 kwargs 传递
                        instance = attribute(**analyzer_conf)
                        found_analyzers.append(instance)
                        logger.info(f"已加载分析器: {class_name}，配置: {analyzer_conf}")
                    except TypeError as e:
                        logger.error(f"无法实例化 {class_name}: {e}。请检查 __init__ 参数与配置是否匹配。")
                        
        except Exception as e:
            logger.error(f"加载模块 {name} 出错: {e}")

    return found_analyzers
