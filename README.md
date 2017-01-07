# Backup Scripts

## AWS S3
1. Make virtual enviroment and install python requirements `make setup`
2. Create a `.boto` config file in your home directory with the following content
````
    [Credentials]
    aws_access_key_id = <your aws access key id>
    aws_secret_access_key = <your aws secret access key>
````
3. Run the commands by:
    * Sync folder to bucket - `make aws ARGS="-f <bucket name> <root folder>"`
    * Sync bucket to folder - `make aws ARGS="-b <bucket name> <root folder>"`
