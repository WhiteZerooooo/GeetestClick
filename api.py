import json
import time
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import httpx
from crack import Crack
from model import Model

app = FastAPI()

@app.get("/verify")
async def verify(gt: str, challenge: str):
    """
    极验验证码破解API
    参数:
        gt: 从极验获取的gt值
        challenge: 从极验获取的challenge值
    """
    start_time = time.time()
    result_data = {
        "success": False,
        "message": "",
        "data": {},
        "time_used": 0
    }

    try:
        # 初始化破解器
        crack = Crack(gt, challenge)

        # 获取验证类型
        crack.gettype()

        # 获取c和s参数
        crack.get_c_s()

        # 等待0.5秒
        time.sleep(0.5)

        # 发送ajax请求
        crack.ajax()

        model = Model()

        for retry in range(6):
            # 获取验证码图片
            pic_content = crack.get_pic(retry)

            # 检测图片
            small_img, big_img = model.detect(pic_content)

            # 文字配对
            result_list = model.siamese(small_img, big_img)
            
            point_list = []
            for i in result_list:
                left = str(round((i[0] + 30) / 333 * 10000))
                top = str(round((i[1] + 30) / 333 * 10000))
                point_list.append(f"{left}_{top}")

            # 验证结果
            result = json.loads(crack.verify(point_list))
            
            if result["data"]["result"] == "success":
                result_data["success"] = True
                result_data["data"] = result["data"]
                break

    except Exception as e:
        result_data["message"] = str(e)
        raise HTTPException(status_code=500, detail=result_data)

    finally:
        result_data["time_used"] = time.time() - start_time

    return JSONResponse(content=result_data)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)