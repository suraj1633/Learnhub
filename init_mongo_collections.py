from utils.mongo_utils import db

def create_collections():
    collections = {
        "users": [],
        "courses": [],
        "enrollments": [],
        "videos": [],
        "reviews": [],
        # Add more as needed
    }

    for name, indexes in collections.items():
        if name not in db.list_collection_names():
            db.create_collection(name)
        for index in indexes:
            db[name].create_index(index)

if __name__ == "__main__":
    create_collections()
    print("MongoDB collections created (if not already present).") 