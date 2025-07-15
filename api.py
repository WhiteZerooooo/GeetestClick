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
        crack.get_type()
        crack.get_c_s()
        time.sleep(0.5)
        model = Model()

        for retry in range(6):
            # 获取验证码图片
            pic_content = crack.get_pic(retry)
            small_img, big_img = model.detect(pic_content)
            result_list = model.siamese(small_img, big_img)
            
            point_list = []
            for i in result_list:
                left = str(round((i[0] + 30) / 333 * 10000))
                top = str(round((i[1] + 30) / 333 * 10000))
                point_list.append(f"{left}_{top}")

            # 验证结果
            # result = json.loads(crack.verify(point_list))

            result_data["success"] = True
            result_data["codes"] = point_list
            result_data["c"] = crack.c
            result_data["s"] = crack.s
            result_data["pic"] = crack.pic_path
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