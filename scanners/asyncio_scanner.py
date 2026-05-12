import asyncio, time

async def scan_port(host, port):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=0.5
        )
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

async def scan_host_limited(host, ports, max_concurrent=100):
    sem = asyncio.Semaphore(max_concurrent)
    async def limited(p):
        async with sem:
            await asyncio.sleep(0)
            return await scan_port(host, p)
    results = await asyncio.gather(*[limited(p) for p in ports])
    return sorted(p for p in results if p)

# Mide en los mismos niveles: 50, 200, 500
for rate in [50, 200, 500]:
    start = time.perf_counter()
    open_ports = asyncio.run(scan_host_limited("127.0.0.1", range(1, 1025), rate))
    print(f"rate={rate}: {time.perf_counter()-start:.2f}s  ports={open_ports}")
