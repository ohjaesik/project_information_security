def pytest_addoption(parser):
    parser.addoption(
        "--rich-dashboard",
        action="store_true",
        default=False,
        help="Show rich dashboard output for pipeline tests",
    )


import pytest


@pytest.fixture
def rich_dashboard(request):
    """
    테스트 함수에서 rich_dashboard(rich_dashboard: bool) 형태로 받으면,
    커맨드라인 옵션 --rich-dashboard 값(True/False)을 전달해준다.
    """
    return request.config.getoption("--rich-dashboard")