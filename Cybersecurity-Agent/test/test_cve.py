from mcp_tools.vulnerability.tools.nvd_service import search_keyword, search_product
from mcp_tools.vulnerability.tools.osv_service import maven_lookup, package_lookup


def print_result(title, result):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)
    print("Status:", result.get("status"))

    if result.get("status") == "success":
        data = result.get("data", {})
        count = data.get("count", 0)
        print("Count:", count)

        # Show only first result for readability
        items = (
            data.get("results")
            or data.get("vulnerabilities")
            or []
        )

        if items:
            print("Sample:", items[0])
    else:
        print("Error:", result.get("error"))


# -------------------------
# NVD Keyword Tests
# -------------------------

print_result(
    "Test 1: NVD Keyword (Expected: results)",
    search_keyword("log4j")
)

print_result(
    "Test 2: NVD Keyword (Expected: empty)",
    search_keyword("nonexistentproductxyz")
)


# -------------------------
# NVD Product Tests
# -------------------------

print_result(
    "Test 3: Product + Version (Apache)",
    search_product("apache tomcat", "9.0.0")
)

print_result(
    "Test 4: Product with unlikely version (Expected: empty)",
    search_product("apache tomcat", "99.99.99")
)


# -------------------------
# OSV Maven Tests
# -------------------------

print_result(
    "Test 5: Maven dependency (Expected: vulnerabilities)",
    maven_lookup("log4j-core", "2.14.1")
)

print_result(
    "Test 6: Maven dependency safe version (Expected: 0)",
    maven_lookup("log4j-core", "2.20.0")
)


# -------------------------
# OSV Generic Ecosystem Tests
# -------------------------

print_result(
    "Test 7: PyPI package",
    package_lookup("django", "2.2.0", "PyPI")
)

print_result(
    "Test 8: npm package",
    package_lookup("lodash", "4.17.19", "npm")
)

print_result(
    "Test 9: Unknown package (Expected: 0)",
    package_lookup("fake-package-xyz", "1.0.0", "npm")
)