import json

def lambda_handler(event, context):

    print("Security detection triggered")

    print(json.dumps(event))

    user = event.get("detail", {}).get("requestParameters", {}).get("userName")

    if user:
        print(f"Detected IAM user creation: {user}")

    return {
        "statusCode": 200,
        "body": "Security event processed"
    }