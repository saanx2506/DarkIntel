import traceback


class BaseCollector:
    name = "base"
    timeout = 30

    async def fetch_raw(self) -> list[dict]:
        raise NotImplementedError

    def normalize(self, raw: dict) -> tuple[dict | None, dict | None]:
        raise NotImplementedError

    async def collect(self) -> list[tuple[dict | None, dict | None]]:
        raw_items = await self.fetch_raw()
        results = []
        for item in raw_items:
            try:
                normalized = self.normalize(item)
                results.append(normalized)
            except Exception as e:
                print(f"[{self.name}] normalize() failed on item:")
                print(f"[{self.name}]   raw item: {item}")
                print(f"[{self.name}]   error type: {type(e).__name__}")
                print(f"[{self.name}]   error message: {e!r}")
                traceback.print_exc()
                print(f"[{self.name}] ---")
        return results