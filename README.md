# driver-did-polygonid
Driver for the polygonid DID method. 
[Specification](https://github.com/0xPolygonID/did-polygonid).

## How to run locally:
1. Create file `resolvers.settings.yaml` with resolver settings:
    ```yaml
    polygon:
        mumbai:
            contractAddress: "0xf6..."
            networkURL: "https://polygon-mumbai..."
    ```
2. Build docker container:
    ```bash
    docker build -t driver-did-polygonid:local .
    ```
3. Run docker conainer:
    ```bash
    docker run -p 8080:8080 driver-did-polygonid:local
    ```

## How to run e2e tests:
1. Create file `resolvers.settings.yaml` with resolver settings:
    ```yaml
    polygon:
        mumbai:
            contractAddress: "0x134B1BE34911E39A8397ec6289782989729807a4"
            networkURL: "<POLYGON_MUMBAI_RPC_URL>"
    ```
2. Build docker container:
    ```bash
    docker build -t driver-did-polygonid:local .
    ```
3. Run docker conainer:
    ```bash
    docker run -p 8080:8080 driver-did-polygonid:local
    ```
4. To run postman tests, you have two options. First, you can import the `tests/e2e/users_tests.postman_collection.json` collection into Postman. Alternatively, you can install Newman and run the tests from the command line interface.:
    ```bash
    npm install -g newman
    ```
5. Run users e2e tests:
    ```bash
    newman run tests/e2e/users_tests.postman_collection.json
    ```
