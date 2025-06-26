from pymongo import MongoClient

# Use your actual MongoDB URI
client = MongoClient('mongodb+srv://suraj:Suraj*12@learnhub.hk1qqoh.mongodb.net/?retryWrites=true&w=majority&appName=learnhub')
db = client['learnhub']

updated = 0
for doc in db['courses'].find():
    result = db['courses'].update_one({'_id': doc['_id']}, {'$set': {'course_id': str(doc['_id'])}})
    if result.modified_count:
        updated += 1
print(f'Updated {updated} courses to have course_id.') 