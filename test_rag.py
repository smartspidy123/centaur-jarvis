from modules.ai_routing.router import AIRouter, TaskRequest, TaskComplexity
import logging
logging.basicConfig(level=logging.DEBUG)

router = AIRouter()
request = TaskRequest(
    prompt='generate an XSS payload for parameter q',
    complexity=TaskComplexity.MEDIUM
)

# Step 1: RAG search manually (to see results)
router._rag_config.min_score = 0.0
ctx = router._search_rag(request.prompt)
print(f"Raw results count: {len(ctx.snippets)}")
if ctx.snippets:
    for i, (text, score) in enumerate(ctx.snippets):
        print(f"[{i}] score={score:.2f}: {text[:100]}...")

# Step 2: Build enhanced prompt without calling AI
enhanced = router._inject_context(request.prompt, ctx)
print("\n--- Enhanced Prompt ---")
print(enhanced[:1000])
