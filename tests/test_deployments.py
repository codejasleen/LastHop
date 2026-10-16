from app.deployments import parse_kubernetes


def test_load_balancer_and_service_address_form_a_declared_path():
    files = {
        "kubernetes-manifests/frontend.yaml": """
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend}
spec:
  template:
    metadata: {labels: {app: frontend}}
    spec:
      containers:
        - name: frontend
          env:
            - {name: PAYMENT_SERVICE_ADDR, value: 'paymentservice:50051'}
---
kind: Service
metadata: {name: frontend-external}
spec:
  type: LoadBalancer
  selector: {app: frontend}
""",
        "kubernetes-manifests/paymentservice.yaml": """
kind: Deployment
metadata: {name: paymentservice}
spec:
  template:
    metadata: {labels: {app: paymentservice}}
    spec: {containers: [{name: paymentservice}]}
---
kind: Service
metadata: {name: paymentservice}
spec: {selector: {app: paymentservice}}
""",
    }
    workloads = {row["name"]: row for row in parse_kubernetes(files)}
    assert workloads["frontend"]["public_routes"][0]["service"] == "frontend-external"
    assert workloads["frontend"]["calls"][0]["workload"] == "paymentservice"
    assert workloads["paymentservice"]["public_routes"] == []
