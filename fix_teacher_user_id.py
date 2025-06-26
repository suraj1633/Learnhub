from pymongo import MongoClient
from bson import ObjectId

client = MongoClient('mongodb+srv://suraj:Suraj*12@learnhub.hk1qqoh.mongodb.net/?retryWrites=true&w=majority&appName=learnhub')
db = client['learnhub']

db['users'].update_one(
    {'_id': ObjectId('685d689c938071e63c4078f4')},
    {'$set': {'user_id': '685d689c938071e63c4078f4'}}
)
print('Teacher user_id set.') 