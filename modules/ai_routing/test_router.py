from modules.ai_routing.router import get_router, TaskRequest, TaskComplexity

router = get_router()
print("Available providers:", router.get_available_providers())

# Test local (Ollama)
req_local = TaskRequest(
    task_type="test_local",
    prompt="What is the capital of France?",
    context_length=50,
    complexity=TaskComplexity.SIMPLE,
)
print("\n--- Testing local LLM ---")
resp_local = router.generate(req_local)
print("Response:", resp_local)

# Test Groq (if available)
if router.get_available_providers().get("groq"):
    req_groq = TaskRequest(
        task_type="test_groq",
        prompt="Explain quantum computing in one sentence.",
        context_length=50,
        complexity=TaskComplexity.MEDIUM,
    )
    print("\n--- Testing Groq API ---")
    resp_groq = router.generate(req_groq)
    print("Response:", resp_groq)
else:
    print("\nGroq not available (check API key)")
