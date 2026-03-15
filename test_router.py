from modules.ai_routing.router import get_router, TaskRequest, TaskComplexity

router = get_router()
print("Available providers:", router.get_available_providers())

req = TaskRequest(
    task_type="test_local",
    prompt="What is the capital of France?",
    context_length=50,
    complexity=TaskComplexity.SIMPLE,
)
print("\n--- Testing local LLM ---")
resp = router.generate(req)
print("Response:", resp)

# Test Groq if available
if router.get_available_providers().get("groq"):
    req_groq = TaskRequest(
        task_type="test_groq",
        prompt="Explain AI in one sentence.",
        context_length=50,
        complexity=TaskComplexity.MEDIUM,
    )
    print("\n--- Testing Groq API ---")
    resp_groq = router.generate(req_groq)
    print("Response:", resp_groq)
