onmessage = async function(e) {
    console.log('Worker started with level:', e.data.level, 'prefix:', e.data.prefix);
    
    const { url, level: levelStr, prefix } = e.data;
    const level = parseInt(levelStr, 10);
    
    const encoder = new TextEncoder();
    
    let i = 0;
    
    while (true) {
        const c = btoa(i+"");
        const sol = prefix + c;
        
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(sol));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        
        const fullHashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        if (fullHashHex.startsWith('0'.repeat(level))) {
            console.log('Solution found after', i, 'attempts');
            postMessage({ 
                done: true, 
                solution: sol,
                hash: fullHashHex,
            });
            break;
        }
        
        i++;
        
        if (i % 1000 === 0) {
            postMessage({ progress: i });
        }
    }
}