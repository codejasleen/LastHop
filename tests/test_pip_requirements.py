from app.advisories import is_affected
from app.pip_requirements import parse_requirements


def test_pinned_requirements_are_positive_evidence_only():
    deps, edges = parse_requirements("urllib3==2.6.3\nrequests>=2.0\n-r more.txt\nJinja2==3.1.6 # pinned\n")
    assert [(dep.name, dep.version) for dep in deps] == [("urllib3", "2.6.3"), ("jinja2", "3.1.6")]
    assert edges == [("", "urllib3"), ("", "jinja2")]
    assert is_affected("2.6.3", ">=1.26.0 <2.8.0", "PyPI") is True
    assert is_affected("2.8.0", ">=1.26.0 <2.8.0", "PyPI") is False
