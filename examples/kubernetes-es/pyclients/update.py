from elasticsearch import Elasticsearch
es = Elasticsearch(['elasticsearch.default.svc.cluster.local:9200'])

book1 = { 'author': 'sidious', 'title': 'Why Convert a Jedi!' }

book2 = { 'author': 'sidious', 'title': 'Force is Same for Dark Side and Jedi' }

print("Creating/Updating Books")

res = es.index(index="sidious", doc_type="tome", id=1, body=book1)

print(res['result'], ": ", res)

res = es.index(index="sidious", doc_type="tome", id=2, body=book2)

print(res['result'], ": ", res)
