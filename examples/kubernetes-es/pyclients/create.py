from elasticsearch import Elasticsearch
es = Elasticsearch(['192.168.99.101:31608'])

book1 = { 'author': 'sidious', 'title': 'Convert Jedi to Dark Side: 101' }

book2 = { 'author': 'sidious', 'title': 'Welcome to the Dark Side' }


res = es.index(index="sidious", doc_type="tome", id=1, body=book1)


print(res['result'], ": ", res)

res = es.index(index="sidious", doc_type="tome", id=2, body=book2)

print(res['result'], ": ", res)

res = es.search(index="sidious", body={"query": {"match_all": {}}})

print("Got %d Hits:" % res['hits']['total'])
for hit in res['hits']['hits']:
    print(hit)

res = es.get(index="sidious", doc_type="tome", id=1)
print(res['_source'])


