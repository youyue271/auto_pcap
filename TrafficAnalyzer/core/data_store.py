import pandas as pd
import sqlite3
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class DataStore:
    def __init__(self, use_db=False, db_path="traffic_data.db"):
        self.use_db = use_db
        self.db_path = db_path
        self.df = pd.DataFrame()
        self.conn = None
        
        if self.use_db:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._init_db()
            logger.info(f"DataStore 已初始化 (SQLite 模式): {self.db_path}")
        else:
            logger.info("DataStore 已初始化 (内存模式)")

    def _init_db(self):
        # 简单初始化，实际可能需要根据 schema 动态创建
        pass

    def save(self, data: List[Dict]):
        if not data:
            return
            
        new_df = pd.DataFrame(data)
        
        if self.use_db:
            # 将 DataFrame 写入 SQLite
            # if_exists='append' 会自动创建表（如果不存在）
            # 假设所有特征都在同一张表 'features' 中，或者需要根据 analyzer 分表
            # 这里简单处理，全部存入 'features'
            try:
                # 确保 columns 是字符串类型，避免 dict 嵌套导致的问题 (sqlite 不支持 array/dict)
                # 实际生产中可能需要序列化复杂字段
                str_df = new_df.astype(str) 
                str_df.to_sql('features', self.conn, if_exists='append', index=False)
            except Exception as e:
                logger.error(f"数据库写入错误: {e}")
        else:
            self.df = pd.concat([self.df, new_df], ignore_index=True)

    def get_all(self) -> pd.DataFrame:
        if self.use_db:
            return pd.read_sql("SELECT * FROM features", self.conn)
        else:
            return self.df

    def get_by_flow(self, flow_id: str) -> List[Dict]:
        """
        获取指定 Flow 的所有记录，按时间排序
        """
        if self.use_db:
            query = f"SELECT * FROM features WHERE flow_id = '{flow_id}' ORDER BY timestamp"
            return pd.read_sql(query, self.conn).to_dict('records')
        else:
            if 'flow_id' not in self.df.columns:
                return []
            filtered = self.df[self.df['flow_id'] == flow_id]
            return filtered.sort_values('timestamp').to_dict('records')
    
    def get_grouped_by(self, key: str):
        """
        通用分组查询。
        返回 (group_id, list_of_dicts) 的生成器
        """
        if self.use_db:
            # 检查列是否存在以避免错误
            try:
                distinct_query = f"SELECT DISTINCT {key} FROM features WHERE {key} IS NOT NULL"
                ids = pd.read_sql(distinct_query, self.conn)[key].tolist()
                for i in ids:
                    q = f"SELECT * FROM features WHERE {key} = ? ORDER BY timestamp"
                    yield i, pd.read_sql(q, self.conn, params=(i,)).to_dict('records')
            except Exception as e:
                logger.error(f"按 {key} 分组错误: {e}")
                return
        else:
            if key not in self.df.columns:
                return
            # 过滤 None/NaN
            valid_df = self.df[self.df[key].notna()]
            for gid, group in valid_df.groupby(key):
                yield gid, group.sort_values('timestamp').to_dict('records')

    def get_grouped_flows(self):
        """
        已弃用: 请使用 get_grouped_by('flow_id')
        """
        return self.get_grouped_by('flow_id')


    def close(self):
        if self.conn:
            self.conn.close()
