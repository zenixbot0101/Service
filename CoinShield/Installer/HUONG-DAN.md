# Hướng Dẫn Cài Đặt CoinShield

## Cài Đặt Nhanh

### Cài đặt thông thường (có hiển thị)
```powershell
# Chạy với quyền Administrator
.\install.ps1
```

### Cài đặt im lặng (silent installation)
```powershell
# Chạy với quyền Administrator - không có output, không có prompts
.\install.ps1 -Silent
```

## Các Tùy Chọn Cài Đặt

### Chọn thư mục cài đặt khác
```powershell
.\install.ps1 -InstallDir "D:\Security\CoinShield"
```

### Chọn chế độ hoạt động
```powershell
# Chế độ Monitor (an toàn - chỉ ghi log, không tắt process)
.\install.ps1 -Mode Monitor

# Chế độ Enforcement (tự động tắt process mining)
.\install.ps1 -Mode Enforcement -Silent

# Chế độ Emergency (tắt máy khi phát hiện mining)
.\install.ps1 -Mode Emergency
```

## Tính Năng Đã Có Sẵn

✅ **Tự động khởi động sau khi cài** - Service sẽ tự động chạy ngay sau khi cài đặt xong

✅ **Hỗ trợ cài đặt im lặng** - Dùng flag `-Silent` để triển khai tự động

✅ **Tự động khởi động lại service** - Khi service bị crash, Windows sẽ tự động restart (cấu hình SCM recovery)

✅ **Yêu cầu quyền Administrator** - Cần UAC để cài đặt và gỡ bỏ

✅ **Sử dụng tài nguyên thấp** - Mục tiêu < 1% CPU khi rảnh, < 100 MB RAM

✅ **Chạy nền hoàn toàn** - Không có giao diện, chạy như Windows Service

## Cài Đặt Đã Thực Hiện

Sau khi chạy installer:

1. **Service chính**: CoinShield (tự động khởi động)
2. **Watchdog**: CoinShieldWatchdog (giám sát service chính)
3. **Vị trí cài đặt**: `C:\Program Files\CoinShield\`
4. **Thư mục log**: `C:\ProgramData\CoinShield\Logs\`
5. **Cấu hình**: `config.json` và `allowlist.json`

## Kiểm Tra Sau Khi Cài

Xem trạng thái service:
```powershell
Get-Service CoinShield, CoinShieldWatchdog
```

Xem Event Log:
```powershell
Get-EventLog -LogName Application -Source CoinShield -Newest 5
```

## Gỡ Bỏ

```powershell
# Chạy với quyền Administrator
.\uninstall.ps1

# Xóa luôn cả log files
.\uninstall.ps1 -RemoveLogs
```

## Yêu Cầu Hệ Thống

- Windows 10 hoặc Windows Server 2016+
- .NET 10 Runtime (x64)
- Quyền Administrator
- ~100 MB dung lượng đĩa

## Triển Khai Tự Động

### Cài qua mạng (Group Policy / SCCM)
```powershell
powershell.exe -ExecutionPolicy Bypass -File "\\server\share\install.ps1" -Silent -Mode Monitor
```

### Cài trong CI/CD pipeline
```powershell
.\install.ps1 -Silent -Mode Enforcement -InstallDir "C:\Program Files\CoinShield"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

## Cấu Hình

Sau khi cài đặt, bạn có thể chỉnh sửa:
- `C:\Program Files\CoinShield\config.json`

**Khởi động lại service** sau khi thay đổi cấu hình:
```powershell
Restart-Service CoinShield
```

## Các Chế Độ Hoạt Động

| Chế độ | Mô tả | Hành động |
|--------|-------|-----------|
| **Monitor** | An toàn nhất | Chỉ ghi log, không tắt process |
| **Enforcement** | Cân bằng | Tự động tắt process mining |
| **Emergency** | Nghiêm ngặt nhất | Tắt máy khi phát hiện mining |

## Tài Nguyên & Log

Tất cả hoạt động được ghi vào:
- **Windows Event Log**: Application → CoinShield
- **JSON Logs**: `C:\ProgramData\CoinShield\Logs\`

Để xem log chi tiết:
```
Event Viewer → Windows Logs → Application → Lọc theo nguồn: CoinShield, CoinShieldWatchdog
```

## Câu Hỏi Thường Gặp

**Q: Service có tự khởi động sau khi restart máy không?**
A: Có, service được cấu hình Automatic (Delayed Start)

**Q: Nếu service bị crash thì sao?**
A: Windows sẽ tự động restart service sau 10 giây (tối đa 3 lần)

**Q: Làm sao biết service đang hoạt động?**
A: Dùng lệnh `Get-Service CoinShield` hoặc xem trong Task Manager → Services

**Q: Có thể cài im lặng để triển khai hàng loạt không?**
A: Có, dùng `.\install.ps1 -Silent -Mode Monitor`

**Q: Service ăn bao nhiêu tài nguyên?**
A: Mục tiêu < 1% CPU khi rảnh, < 100 MB RAM

**Q: Có thể thay đổi chế độ sau khi cài không?**
A: Có, sửa file `config.json` và restart service
