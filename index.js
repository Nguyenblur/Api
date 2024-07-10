const { spawn } = require("child_process");

const startChatbot = () => {
    
    const chatbotProcess = spawn("node", ["--trace-warnings", "--async-stack-traces", "main.js"], {
        cwd: __dirname,
        stdio: "inherit",
        shell: true
    });

    chatbotProcess.on("close", async (exitCode) => {
        if (exitCode === 1) {
            startChatbot(); 
        } else if (String(exitCode).startsWith("2")) {
            const delayInSeconds = parseInt(exitCode.replace('2', ''));
            await new Promise((resolve) => setTimeout(resolve, delayInSeconds * 1000));
            startChatbot();
        }
    });

    chatbotProcess.on("error", (error) => {
    });
};

startChatbot();
