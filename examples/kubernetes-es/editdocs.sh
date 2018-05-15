curl -s -H "Content-Type: application/json" -X POST  -d '{ "subject":"Jedi Conversion", "author":"darth sidious", "description":"Beginners Guide to Convert Jedi to Dark Side" }' elasticsearch.default.svc.cluster.local:9200/sithorder/secretdocs/101

curl -s -H "Content-Type: application/json" -X POST  -d '{ "subject":"Jedi Conversion", "author":"darth sidious", "description":"How to Keep on Dark Side" }' elasticsearch.default.svc.cluster.local:9200/sithorder/secretdocs/202

