const fs = require('fs');
const path = require('path');
const { API_ENDPOINTS } = require('./api-hasher');



const scriptsDir = path.join(__dirname, '../assets/scripts');
const publicAssetsDir = path.join(__dirname, '../../public/dist/assets');

async function obfuscateScripts() {
    console.log('🔒 Starting API endpoint obfuscation in client scripts...');

    const files = fs.readdirSync(scriptsDir).filter(f => f.endsWith('.js'));

    if (fs.existsSync(publicAssetsDir)) {
        const builtFiles = fs.readdirSync(publicAssetsDir).filter(f => f.endsWith('.js'));
        builtFiles.forEach(f => {
            files.push(path.join(publicAssetsDir, f));
        });
    }

    let replacementCount = 0;

    for (const file of files) {
        const filePath = file.includes(publicAssetsDir) ? file : path.join(scriptsDir, file);

        try {
            let content = fs.readFileSync(filePath, 'utf8');
            let modified = false;

            
            Object.keys(API_ENDPOINTS).forEach(original => {
                const hashed = API_ENDPOINTS[original];

                
                
                const regex = new RegExp(`(['"\`])${original.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(['"\`])`, 'g');

                if (regex.test(content)) {
                    content = content.replace(regex, `$1${hashed}$2`);
                    modified = true;
                    replacementCount++;
                }
            });

            if (modified) {
                fs.writeFileSync(filePath, content);
                console.log(`✅ Obfuscated API calls in: ${path.basename(filePath)}`);
            }
        } catch (error) {
            console.error(`❌ Error obfuscating ${file}:`, error.message);
        }
    }

    console.log(`🎉 API obfuscation complete! Replaced ${replacementCount} endpoints.`);
}

if (require.main === module) {
    obfuscateScripts().catch(console.error);
}

module.exports = obfuscateScripts;
