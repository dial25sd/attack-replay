from typing import Any, Optional, Type, TypeVar

from bson import ObjectId
from pymongo import MongoClient

from arf_io.exceptions import ArfDbError, ExceptionHandler
from arf_io.ui import ArfLogger
from utils import IPAddress, Serializer


class DbAdapter:
    T = TypeVar('T')

    def __init__(self, db_host: IPAddress, db_port: int, db_name: str):
        self.logger = ArfLogger.instance()
        self.client = self.__get_db_connection(db_host, db_port)
        self.db = self.client[db_name]
        self.exc_handler = ExceptionHandler()

    def __get_db_connection(self, db_host: IPAddress, db_port: int) -> MongoClient:
        try:
            client = MongoClient(str(db_host), db_port)
            client.server_info()
            self.logger.success("Connected to DB!")
            return client
        except Exception as e:
            raise ArfDbError(f'Cannot connect to MongoDB: {e}.') from e

    def __get_collection(self, collection_name: str):
        return self.db[collection_name]

    def create_one(self, collection_name: str, data: T) -> Optional[ObjectId]:
        try:
            result = self.__get_collection(collection_name).insert_one(Serializer.serialize_dataclass(data))
            self.logger.debug(f"Document inserted in collection '{collection_name}' with id {result.inserted_id}.", 1)
            return result.inserted_id
        except Exception as e:
            self.exc_handler.handle(e, msg=f"Error inserting document in collection '{collection_name}': {e}")
            return None

    def create_many(self, collection_name: str, data_list: list[T]) -> list[ObjectId]:
        try:
            data_list = [Serializer.serialize_dataclass(item) for item in data_list]
            filtered_data_list = [x for x in data_list if x is not None]
            if not filtered_data_list:
                self.logger.debug(f"No entities given for insertion into DB. Skipping.", 1)
                return []
            result = self.__get_collection(collection_name).insert_many(filtered_data_list)
            self.logger.debug(f"{len(result.inserted_ids)} document(s) inserted in '{collection_name}'.", 1)
            return result.inserted_ids
        except Exception as e:
            self.exc_handler.handle(e, msg=f"Error inserting documents in collection '{collection_name}': {e}")
            return []

    def read_many(self, collection_name: str, dataclass: Type[T], query: Optional[dict[str, Any]] = None,
                  projection: Any = None) -> list[T]:
        collection = self.__get_collection(collection_name)
        try:
            query = query or {}
            cursor = collection.find(query, projection)
            documents = []
            for document in cursor:
                obj_dict = {k: v for k, v in document.items() if k in dataclass.__annotations__}
                obj = dataclass(**obj_dict)
                documents.append(obj)
            return documents
        except Exception as e:
            self.exc_handler.handle(e,
                                    msg=f"Error reading documents from collection '{collection_name}' using query '{query}': {e}")
            return []

    def read_one(self, collection_name: str, dataclass: Type[T], query: Optional[dict[str, Any]] = None,
                 projection: Any = None, pipeline: Any = None) -> Optional[T]:
        collection = self.__get_collection(collection_name)
        try:
            query = query or {}
            if pipeline is not None:
                document = collection.aggregate(pipeline).next()
            else:
                document = collection.find_one(query, projection)
            if document:
                obj_dict = {k: v for k, v in document.items() if k in dataclass.__annotations__}
                return dataclass(**obj_dict)
            else:
                return None
        except StopIteration:
            return None
        except Exception as e:
            self.exc_handler.handle(e,
                                    msg=f"Error reading document from collection '{collection_name}' using query '{query}': {e}")
            return None

    def read_and_delete_all(self, collection_name: str) -> list[dict]:
        documents = []
        collection = self.__get_collection(collection_name)
        try:
            while True:
                document = collection.find_one_and_delete({})
                if not document:
                    break
                documents.append(document)
            return documents
        except Exception as e:
            self.exc_handler.handle(e,
                                    msg=f"Error reading document from collection '{collection_name}' using query '{query}': {e}")
            return []

    def update(self, collection_name: str, query: dict[str, Any], update: dict[str, Any], multi: bool = False) -> int:
        collection = self.__get_collection(collection_name)
        try:
            if multi:
                result = collection.update_many(query, update)
            else:
                result = collection.update_one(query, update)
            self.logger.debug(f"Updated {result.modified_count} document(s) in collection '{collection_name}'.", 1)
            return result.modified_count
        except Exception as e:
            self.exc_handler.handle(e, msg=f"Error updating documents: {e}")
            return 0

    def delete(self, collection_name: str, query: dict[str, Any], multi: bool = False) -> int:
        collection = self.__get_collection(collection_name)
        try:
            if multi:
                result = collection.delete_many(query)
            else:
                result = collection.delete_one(query)
            self.logger.debug(f"Deleted {result.deleted_count} document(s) from collection '{collection_name}'.", 2)
            return result.deleted_count
        except Exception as e:
            self.exc_handler.handle(e,
                                    msg=f"Error while deleting documents from collection '{collection_name}' using query '{query}': {e}")
            return 0

    def drop_collection(self, collection_name: str) -> None:
        try:
            self.db.drop_collection(collection_name)
            self.logger.debug(f"Collection '{collection_name}' dropped.", 2)
        except Exception as e:
            self.exc_handler.handle(e, msg=f"Error while dropping collection '{collection_name}': {e}")
