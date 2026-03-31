# ADC INDIVIDUAL EVALUATION

## Author
- **Name:** André Tavares
- **Number:** 67161

## Build and deployment

Build the project:
````
mvn clean package
````

Deploy to Google App Engine:
````
mvn appengine:deploy -Dapp.deploy.projectId=<your-proj-id> -Dapp.deploy.version=<version-number>
````

## Testing

You can find some testes I did on the tests folder. If you want some new test I left a README in each operation folder to help with the operations.


For more information please visit:
````
https://individual-evaluation-491717.oa.r.appspot.com/index.html
````

**Dont forget you need someting like the postman to test it**

