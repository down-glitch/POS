using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddOpenApi();
builder.Services.AddHttpClient();

var app = builder.Build();

// Init Database Schema & Seed Data
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await DbInitializer.InitAsync(db);
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseDefaultFiles();
app.UseStaticFiles();

// Helper log function
async Task LogActionAsync(AppDbContext db, string username, string role, string action, string entity, string details)
{
    db.SystemLogs.Add(new SystemLog
    {
        CreatedAt = DateTime.UtcNow,
        Username = string.IsNullOrWhiteSpace(username) ? "System" : username,
        Role = string.IsNullOrWhiteSpace(role) ? "System" : role,
        Action = action,
        Entity = entity,
        Details = details
    });
    await db.SaveChangesAsync();
}

// Helper Pusher trigger function
async Task<bool> TriggerPusherAsync(IHttpClientFactory clientFactory, AppDbContext db, string channel, string eventName, object data)
{
    try
    {
        var configs = await db.SystemConfigs.ToDictionaryAsync(c => c.Key, c => c.Value);
        if (!configs.TryGetValue("pusher_enabled", out var enabled) || enabled != "true")
            return false;

        if (!configs.TryGetValue("pusher_app_id", out var appId) || string.IsNullOrWhiteSpace(appId) ||
            !configs.TryGetValue("pusher_key", out var key) || string.IsNullOrWhiteSpace(key) ||
            !configs.TryGetValue("pusher_secret", out var secret) || string.IsNullOrWhiteSpace(secret) ||
            !configs.TryGetValue("pusher_cluster", out var cluster) || string.IsNullOrWhiteSpace(cluster))
        {
            return false;
        }

        var client = clientFactory.CreateClient();
        var payload = JsonSerializer.Serialize(new
        {
            name = eventName,
            channel = channel,
            data = JsonSerializer.Serialize(data)
        });

        using var md5 = MD5.Create();
        var bodyMd5 = Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLower();

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var path = $"/apps/{appId}/events";
        var queryString = $"auth_key={key}&auth_timestamp={timestamp}&auth_version=1.0&body_md5={bodyMd5}";
        var toSign = $"POST\n{path}\n{queryString}";

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var signature = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(toSign))).ToLower();

        var requestUri = $"https://api-{cluster}.pusher.com{path}?{queryString}&auth_signature={signature}";
        var content = new StringContent(payload, Encoding.UTF8, "application/json");

        var response = await client.PostAsync(requestUri, content);
        return response.IsSuccessStatusCode;
    }
    catch
    {
        return false;
    }
}

// ==========================================
// 0. AUTHENTICATION ENDPOINTS
// ==========================================
var authApi = app.MapGroup("/api/auth");

authApi.MapPost("/login", async (LoginRequest req, AppDbContext db, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
    {
        return Results.BadRequest(new { message = "Username dan password wajib diisi." });
    }

    var user = await db.AppUsers.FirstOrDefaultAsync(u => u.Username.ToLower() == req.Username.Trim().ToLower());
    if (user is null || user.Password != req.Password.Trim())
    {
        return Results.Json(new { message = "Username atau password salah." }, statusCode: 401);
    }

    // Token sederhana berbasis guid & timestamp
    var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user.Username}:{DateTime.UtcNow.Ticks}"));

    await LogActionAsync(db, user.Username, user.Role, "LOGIN", "Auth", $"Pengguna {user.FullName} ({user.Role}) berhasil masuk sistem");

    return Results.Ok(new
    {
        token,
        user = new
        {
            user.Id,
            user.Username,
            user.FullName,
            user.Role
        }
    });
});

authApi.MapPost("/logout", async (AppDbContext db, HttpContext ctx) =>
{
    var user = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Unknown";
    var role = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Unknown";
    await LogActionAsync(db, user, role, "LOGOUT", "Auth", $"Pengguna {user} keluar sistem");
    return Results.Ok(new { message = "Logout berhasil." });
});

authApi.MapGet("/me", async (AppDbContext db, HttpContext ctx) =>
{
    var username = ctx.Request.Headers["X-User"].FirstOrDefault();
    if (string.IsNullOrWhiteSpace(username)) return Results.Unauthorized();

    var user = await db.AppUsers.FirstOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());
    return user is null ? Results.Unauthorized() : Results.Ok(new { user.Id, user.Username, user.FullName, user.Role });
});

// ==========================================
// 1. PRODUCT ENDPOINTS
// ==========================================
var productsApi = app.MapGroup("/api/products");

productsApi.MapGet("/", async (AppDbContext db, string? search) =>
{
    var query = db.Products.AsQueryable();
    if (!string.IsNullOrWhiteSpace(search))
    {
        query = query.Where(p => p.Name.ToLower().Contains(search.ToLower()) || p.Barcode.Contains(search));
    }
    return Results.Ok(await query.OrderBy(p => p.Name).ToListAsync());
});

productsApi.MapGet("/{id:int}", async (int id, AppDbContext db) =>
    await db.Products.FindAsync(id) is Product product ? Results.Ok(product) : Results.NotFound());

productsApi.MapPost("/", async (Product product, AppDbContext db, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(product.Name) || product.Price < 0 || product.Stock < 0)
    {
        return Results.BadRequest(new { message = "Nama wajib diisi, harga dan stok tidak boleh negatif." });
    }

    db.Products.Add(product);
    await db.SaveChangesAsync();

    // Catat mutasi awal stok
    if (product.Stock > 0)
    {
        db.StockCards.Add(new StockCard
        {
            ProductId = product.Id,
            ProductName = product.Name,
            CreatedAt = DateTime.UtcNow,
            MovementType = "STOK_AWAL",
            ReferenceNumber = $"PROD-{product.Id}",
            QuantityChange = product.Stock,
            StockAfter = product.Stock,
            PerformedBy = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin",
            Notes = "Saldo stok awal saat produk dibuat"
        });
        await db.SaveChangesAsync();
    }

    await LogActionAsync(db, ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin", ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Admin", "TAMBAH_PRODUK", $"PROD-{product.Id}", $"Menambah produk {product.Name} (Harga: {product.Price}, Stok: {product.Stock})");

    return Results.Created($"/api/products/{product.Id}", product);
});

productsApi.MapPut("/{id:int}", async (int id, Product input, AppDbContext db, HttpContext ctx) =>
{
    var product = await db.Products.FindAsync(id);
    if (product is null) return Results.NotFound();

    var oldStock = product.Stock;
    product.Name = input.Name;
    product.Barcode = input.Barcode;
    product.Price = input.Price;
    product.Stock = input.Stock;

    if (oldStock != input.Stock)
    {
        var diff = input.Stock - oldStock;
        db.StockCards.Add(new StockCard
        {
            ProductId = product.Id,
            ProductName = product.Name,
            CreatedAt = DateTime.UtcNow,
            MovementType = "PENYESUAIAN_MANUAL",
            ReferenceNumber = $"PROD-{product.Id}",
            QuantityChange = diff,
            StockAfter = input.Stock,
            PerformedBy = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin",
            Notes = $"Edit data produk langsung ({oldStock} -> {input.Stock})"
        });
    }

    await db.SaveChangesAsync();
    await LogActionAsync(db, ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin", ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Admin", "EDIT_PRODUK", $"PROD-{product.Id}", $"Memperbarui produk {product.Name}");

    return Results.Ok(product);
});

productsApi.MapDelete("/{id:int}", async (int id, AppDbContext db, HttpContext ctx) =>
{
    var product = await db.Products.FindAsync(id);
    if (product is null) return Results.NotFound();

    db.Products.Remove(product);
    await db.SaveChangesAsync();

    await LogActionAsync(db, ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin", ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Admin", "HAPUS_PRODUK", $"PROD-{id}", $"Menghapus produk {product.Name}");

    return Results.NoContent();
});

// ==========================================
// 2. TRANSACTION / POS ENDPOINTS
// ==========================================
var transactionsApi = app.MapGroup("/api/transactions");

transactionsApi.MapGet("/", async (AppDbContext db) =>
    Results.Ok(await db.Transactions.Include(t => t.Items).OrderByDescending(t => t.CreatedAt).ToListAsync()));

transactionsApi.MapGet("/{id:int}", async (int id, AppDbContext db) =>
    await db.Transactions.Include(t => t.Items).FirstOrDefaultAsync(t => t.Id == id) is Transaction trx
        ? Results.Ok(trx)
        : Results.NotFound());

transactionsApi.MapPost("/", async (CheckoutRequest request, AppDbContext db, IHttpClientFactory clientFactory, HttpContext ctx) =>
{
    if (request.Items == null || request.Items.Count == 0)
    {
        return Results.BadRequest(new { message = "Daftar item belanja kosong." });
    }

    var productIds = request.Items.Select(i => i.ProductId).Distinct().ToList();
    var products = await db.Products.Where(p => productIds.Contains(p.Id)).ToDictionaryAsync(p => p.Id);

    decimal totalAmount = 0;
    var transactionItems = new List<TransactionItem>();
    var user = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Kasir";
    var role = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Kasir";

    foreach (var item in request.Items)
    {
        if (item.Quantity <= 0)
        {
            return Results.BadRequest(new { message = $"Jumlah item id {item.ProductId} harus lebih dari 0." });
        }

        if (!products.TryGetValue(item.ProductId, out var product))
        {
            return Results.BadRequest(new { message = $"Produk ID {item.ProductId} tidak ditemukan." });
        }

        if (product.Stock < item.Quantity)
        {
            return Results.BadRequest(new { message = $"Stok produk '{product.Name}' kurang. Sisa: {product.Stock}, diminta: {item.Quantity}." });
        }

        var subtotal = product.Price * item.Quantity;
        totalAmount += subtotal;
        product.Stock -= item.Quantity;

        transactionItems.Add(new TransactionItem
        {
            ProductId = product.Id,
            ProductName = product.Name,
            Quantity = item.Quantity,
            UnitPrice = product.Price,
            Subtotal = subtotal
        });
    }

    if (request.CashPaid < totalAmount)
    {
        return Results.BadRequest(new { message = $"Uang pembayaran kurang. Total: {totalAmount}, dibayar: {request.CashPaid}." });
    }

    var transaction = new Transaction
    {
        CreatedAt = DateTime.UtcNow,
        TotalAmount = totalAmount,
        CashPaid = request.CashPaid,
        ChangeAmount = request.CashPaid - totalAmount,
        Items = transactionItems
    };

    db.Transactions.Add(transaction);
    await db.SaveChangesAsync();

    // Catat Kartu Stok untuk penjualan
    foreach (var item in transactionItems)
    {
        var prod = products[item.ProductId];
        db.StockCards.Add(new StockCard
        {
            ProductId = prod.Id,
            ProductName = prod.Name,
            CreatedAt = transaction.CreatedAt,
            MovementType = "PENJUALAN",
            ReferenceNumber = $"TRX-{transaction.Id}",
            QuantityChange = -item.Quantity,
            StockAfter = prod.Stock,
            PerformedBy = user,
            Notes = $"Penjualan kasir nota #TRX-{transaction.Id}"
        });
    }

    await db.SaveChangesAsync();

    await LogActionAsync(db, user, role, "TRANSAKSI_KASIR", $"TRX-{transaction.Id}", $"Transaksi senilai Rp {totalAmount:N0} ({transactionItems.Sum(i => i.Quantity)} pcs)");
    await TriggerPusherAsync(clientFactory, db, "pos", "new-sale", new { transactionId = transaction.Id, totalAmount, totalItems = transactionItems.Sum(i => i.Quantity) });

    return Results.Created($"/api/transactions/{transaction.Id}", transaction);
});

// ==========================================
// 3. WAREHOUSE (GUDANG) ENDPOINTS
// ==========================================
var warehouseApi = app.MapGroup("/api/warehouse");

// 3.1 Pemesanan (Purchase Orders)
warehouseApi.MapGet("/po", async (AppDbContext db) =>
    Results.Ok(await db.PurchaseOrders.Include(p => p.Items).OrderByDescending(p => p.CreatedAt).ToListAsync()));

warehouseApi.MapPost("/po", async (CreatePoRequest req, AppDbContext db, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(req.SupplierName) || req.Items == null || req.Items.Count == 0)
    {
        return Results.BadRequest(new { message = "Nama supplier dan daftar barang wajib diisi." });
    }

    var poNumber = $"PO-{DateTime.UtcNow:yyyyMMdd}-{Random.Shared.Next(1000, 9999)}";
    decimal total = 0;
    var poItems = new List<PurchaseOrderItem>();

    foreach (var item in req.Items)
    {
        if (item.QuantityOrdered <= 0 || item.UnitPrice < 0)
        {
            return Results.BadRequest(new { message = "Jumlah dan harga satuan item harus valid." });
        }
        var prod = await db.Products.FindAsync(item.ProductId);
        var prodName = prod?.Name ?? item.ProductName;
        total += item.UnitPrice * item.QuantityOrdered;

        poItems.Add(new PurchaseOrderItem
        {
            ProductId = item.ProductId,
            ProductName = prodName,
            QuantityOrdered = item.QuantityOrdered,
            QuantityReceived = 0,
            UnitPrice = item.UnitPrice
        });
    }

    var user = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Gudang";
    var role = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Gudang";

    var po = new PurchaseOrder
    {
        PoNumber = poNumber,
        SupplierName = req.SupplierName.Trim(),
        Status = "Diproses",
        CreatedAt = DateTime.UtcNow,
        TotalAmount = total,
        Items = poItems
    };

    db.PurchaseOrders.Add(po);
    await db.SaveChangesAsync();

    await LogActionAsync(db, user, role, "BUAT_PO", po.PoNumber, $"Pemesanan ke {po.SupplierName} (Total: Rp {total:N0})");

    return Results.Created($"/api/warehouse/po/{po.Id}", po);
});

warehouseApi.MapPut("/po/{id:int}/cancel", async (int id, AppDbContext db, HttpContext ctx) =>
{
    var po = await db.PurchaseOrders.Include(p => p.Items).FirstOrDefaultAsync(p => p.Id == id);
    if (po is null) return Results.NotFound();

    if (po.Status == "Selesai")
    {
        return Results.BadRequest(new { message = "PO yang sudah selesai tidak dapat dibatalkan." });
    }

    po.Status = "Dibatalkan";
    await db.SaveChangesAsync();

    var user = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Gudang";
    var role = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Gudang";
    await LogActionAsync(db, user, role, "BATAL_PO", po.PoNumber, $"Membatalkan pemesanan {po.PoNumber}");

    return Results.Ok(po);
});

// 3.2 Penerimaan Barang (Goods Receipt)
warehouseApi.MapGet("/receipts", async (AppDbContext db) =>
    Results.Ok(await db.GoodsReceipts.Include(g => g.Items).Include(g => g.Revisions).OrderByDescending(g => g.ReceivedAt).ToListAsync()));

warehouseApi.MapPost("/receipts", async (CreateReceiptRequest req, AppDbContext db, IHttpClientFactory clientFactory, HttpContext ctx) =>
{
    var po = await db.PurchaseOrders.Include(p => p.Items).FirstOrDefaultAsync(p => p.Id == req.PurchaseOrderId);
    if (po is null) return Results.BadRequest(new { message = "PO tidak ditemukan." });

    if (po.Status == "Dibatalkan")
    {
        return Results.BadRequest(new { message = "PO telah dibatalkan." });
    }

    var user = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Gudang";
    var role = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Gudang";
    var grNumber = $"GR-{DateTime.UtcNow:yyyyMMdd}-{Random.Shared.Next(1000, 9999)}";

    var grItems = new List<GoodsReceiptItem>();
    var now = DateTime.UtcNow;

    foreach (var item in req.Items)
    {
        if (item.QuantityReceived <= 0) continue;

        var poItem = po.Items.FirstOrDefault(i => i.ProductId == item.ProductId);
        if (poItem is null) continue;

        poItem.QuantityReceived += item.QuantityReceived;

        var product = await db.Products.FindAsync(item.ProductId);
        if (product != null)
        {
            product.Stock += item.QuantityReceived;

            db.StockCards.Add(new StockCard
            {
                ProductId = product.Id,
                ProductName = product.Name,
                CreatedAt = now,
                MovementType = "PENERIMAAN_PO",
                ReferenceNumber = grNumber,
                QuantityChange = item.QuantityReceived,
                StockAfter = product.Stock,
                PerformedBy = user,
                Notes = $"Penerimaan barang dari {po.PoNumber}"
            });
        }

        grItems.Add(new GoodsReceiptItem
        {
            ProductId = item.ProductId,
            ProductName = poItem.ProductName,
            QuantityReceived = item.QuantityReceived
        });
    }

    if (grItems.Count == 0)
    {
        return Results.BadRequest(new { message = "Tidak ada barang yang diterima." });
    }

    // Cek apakah PO sudah lengkap diterima
    var isFullyReceived = po.Items.All(i => i.QuantityReceived >= i.QuantityOrdered);
    po.Status = isFullyReceived ? "Selesai" : "Sebagian";

    var gr = new GoodsReceipt
    {
        ReceiptNumber = grNumber,
        PurchaseOrderId = po.Id,
        ReceivedAt = now,
        ReceivedBy = user,
        Notes = req.Notes ?? string.Empty,
        Items = grItems
    };

    db.GoodsReceipts.Add(gr);
    await db.SaveChangesAsync();

    await LogActionAsync(db, user, role, "PENERIMAAN_BARANG", grNumber, $"Menerima barang untuk {po.PoNumber} ({grItems.Sum(i => i.QuantityReceived)} pcs)");
    await TriggerPusherAsync(clientFactory, db, "warehouse", "goods-received", new { receiptNumber = grNumber, poNumber = po.PoNumber, totalReceived = grItems.Sum(i => i.QuantityReceived) });

    return Results.Created($"/api/warehouse/receipts/{gr.Id}", gr);
});

// 3.3 Revisi Penerimaan (Penyesuaian Qty / Retur)
warehouseApi.MapPost("/receipts/{id:int}/revise", async (int id, ReviseReceiptRequest req, AppDbContext db, IHttpClientFactory clientFactory, HttpContext ctx) =>
{
    var gr = await db.GoodsReceipts.Include(g => g.Items).FirstOrDefaultAsync(g => g.Id == id);
    if (gr is null) return Results.NotFound(new { message = "Data penerimaan tidak ditemukan." });

    var product = await db.Products.FindAsync(req.ProductId);
    if (product is null) return Results.NotFound(new { message = "Produk tidak ditemukan." });

    if (req.DeltaQuantity == 0)
    {
        return Results.BadRequest(new { message = "Perubahan jumlah barang (Delta) tidak boleh 0." });
    }

    if (product.Stock + req.DeltaQuantity < 0)
    {
        return Results.BadRequest(new { message = $"Stok saat ini ({product.Stock}) tidak mencukupi untuk pengurangan {Math.Abs(req.DeltaQuantity)}." });
    }

    var user = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Gudang";
    var role = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Gudang";
    var now = DateTime.UtcNow;

    product.Stock += req.DeltaQuantity;

    var revision = new ReceiptRevision
    {
        GoodsReceiptId = gr.Id,
        ProductId = product.Id,
        ProductName = product.Name,
        RevisedAt = now,
        RevisedBy = user,
        DeltaQuantity = req.DeltaQuantity,
        Reason = req.Reason?.Trim() ?? "Penyesuaian penerimaan"
    };

    db.ReceiptRevisions.Add(revision);

    db.StockCards.Add(new StockCard
    {
        ProductId = product.Id,
        ProductName = product.Name,
        CreatedAt = now,
        MovementType = "REVISI_PENERIMAAN",
        ReferenceNumber = gr.ReceiptNumber,
        QuantityChange = req.DeltaQuantity,
        StockAfter = product.Stock,
        PerformedBy = user,
        Notes = $"Revisi penerimaan: {revision.Reason}"
    });

    await db.SaveChangesAsync();

    await LogActionAsync(db, user, role, "REVISI_PENERIMAAN", gr.ReceiptNumber, $"Revisi {product.Name} selisih {req.DeltaQuantity} pcs. Alasan: {revision.Reason}");
    await TriggerPusherAsync(clientFactory, db, "warehouse", "receipt-revised", new { receiptNumber = gr.ReceiptNumber, product = product.Name, delta = req.DeltaQuantity, reason = revision.Reason });

    return Results.Ok(revision);
});

// 3.4 Data Stok & Nilai Persediaan
warehouseApi.MapGet("/stock", async (AppDbContext db) =>
{
    var list = await db.Products.OrderBy(p => p.Name).ToListAsync();
    var totalValuation = list.Sum(p => p.Price * p.Stock);
    var totalStock = list.Sum(p => p.Stock);
    var lowStockCount = list.Count(p => p.Stock > 0 && p.Stock <= 5);
    var outOfStockCount = list.Count(p => p.Stock <= 0);

    return Results.Ok(new
    {
        summary = new { totalValuation, totalStock, lowStockCount, outOfStockCount, totalProducts = list.Count },
        products = list
    });
});

// 3.5 Stok Opname
warehouseApi.MapGet("/opname", async (AppDbContext db) =>
    Results.Ok(await db.StockOpnames.Include(s => s.Items).OrderByDescending(s => s.CreatedAt).ToListAsync()));

warehouseApi.MapPost("/opname", async (CreateOpnameRequest req, AppDbContext db, IHttpClientFactory clientFactory, HttpContext ctx) =>
{
    if (req.Items == null || req.Items.Count == 0)
    {
        return Results.BadRequest(new { message = "Daftar item opname kosong." });
    }

    var user = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Gudang";
    var role = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Gudang";
    var opnameNumber = $"SO-{DateTime.UtcNow:yyyyMMdd}-{Random.Shared.Next(1000, 9999)}";
    var now = DateTime.UtcNow;

    var opnameItems = new List<StockOpnameItem>();

    foreach (var item in req.Items)
    {
        var product = await db.Products.FindAsync(item.ProductId);
        if (product is null) continue;

        var systemStock = product.Stock;
        var diff = item.PhysicalStock - systemStock;

        opnameItems.Add(new StockOpnameItem
        {
            ProductId = product.Id,
            ProductName = product.Name,
            SystemStock = systemStock,
            PhysicalStock = item.PhysicalStock,
            Difference = diff
        });

        if (diff != 0)
        {
            product.Stock = item.PhysicalStock;

            db.StockCards.Add(new StockCard
            {
                ProductId = product.Id,
                ProductName = product.Name,
                CreatedAt = now,
                MovementType = "STOK_OPNAME",
                ReferenceNumber = opnameNumber,
                QuantityChange = diff,
                StockAfter = item.PhysicalStock,
                PerformedBy = user,
                Notes = $"Penyesuaian opname ({systemStock} -> {item.PhysicalStock})"
            });
        }
    }

    var opname = new StockOpname
    {
        OpnameNumber = opnameNumber,
        CreatedAt = now,
        PerformedBy = user,
        Notes = req.Notes ?? "Stok Opname Rutin",
        Items = opnameItems
    };

    db.StockOpnames.Add(opname);
    await db.SaveChangesAsync();

    await LogActionAsync(db, user, role, "STOK_OPNAME", opnameNumber, $"Stok opname {opnameItems.Count} produk (Selisih: {opnameItems.Count(i => i.Difference != 0)} item)");
    await TriggerPusherAsync(clientFactory, db, "warehouse", "stock-opname", new { opnameNumber, totalAdjusted = opnameItems.Count(i => i.Difference != 0) });

    return Results.Created($"/api/warehouse/opname/{opname.Id}", opname);
});

// 3.6 Kartu Stok (Ledger Mutasi)
warehouseApi.MapGet("/stock-card", async (AppDbContext db, int? productId) =>
{
    var query = db.StockCards.AsQueryable();
    if (productId.HasValue && productId.Value > 0)
    {
        query = query.Where(s => s.ProductId == productId.Value);
    }
    return Results.Ok(await query.OrderByDescending(s => s.CreatedAt).Take(200).ToListAsync());
});

// ==========================================
// 4. LAPORAN PENJUALAN
// ==========================================
var reportsApi = app.MapGroup("/api/reports");

reportsApi.MapGet("/sales", async (AppDbContext db, string? startDate, string? endDate) =>
{
    var query = db.Transactions.Include(t => t.Items).AsQueryable();

    if (DateTime.TryParse(startDate, out var start))
    {
        var startUtc = DateTime.SpecifyKind(start.Date, DateTimeKind.Utc);
        query = query.Where(t => t.CreatedAt >= startUtc);
    }

    if (DateTime.TryParse(endDate, out var end))
    {
        var endUtc = DateTime.SpecifyKind(end.Date.AddDays(1).AddTicks(-1), DateTimeKind.Utc);
        query = query.Where(t => t.CreatedAt <= endUtc);
    }

    var transactions = await query.OrderByDescending(t => t.CreatedAt).ToListAsync();

    var totalRevenue = transactions.Sum(t => t.TotalAmount);
    var totalTransactions = transactions.Count;
    var totalItemsSold = transactions.SelectMany(t => t.Items).Sum(i => i.Quantity);
    var avgTransaction = totalTransactions > 0 ? totalRevenue / totalTransactions : 0;

    var topProducts = transactions
        .SelectMany(t => t.Items)
        .GroupBy(i => new { i.ProductId, i.ProductName })
        .Select(g => new
        {
            ProductId = g.Key.ProductId,
            ProductName = g.Key.ProductName,
            TotalQuantity = g.Sum(x => x.Quantity),
            TotalRevenue = g.Sum(x => x.Subtotal)
        })
        .OrderByDescending(x => x.TotalQuantity)
        .Take(10)
        .ToList();

    return Results.Ok(new
    {
        summary = new { totalRevenue, totalTransactions, totalItemsSold, avgTransaction },
        topProducts,
        transactions
    });
});

// ==========================================
// 5. USER & ROLE PERMISSION (RBAC)
// ==========================================
var usersApi = app.MapGroup("/api/users");

usersApi.MapGet("/", async (AppDbContext db) =>
    Results.Ok(await db.AppUsers.OrderBy(u => u.Id).ToListAsync()));

usersApi.MapPost("/", async (AppUser user, AppDbContext db, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(user.Username) || string.IsNullOrWhiteSpace(user.Role))
    {
        return Results.BadRequest(new { message = "Username dan role wajib diisi." });
    }

    if (await db.AppUsers.AnyAsync(u => u.Username.ToLower() == user.Username.ToLower()))
    {
        return Results.BadRequest(new { message = "Username sudah digunakan." });
    }

    db.AppUsers.Add(user);
    await db.SaveChangesAsync();

    var actor = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin";
    var actorRole = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Admin";
    await LogActionAsync(db, actor, actorRole, "TAMBAH_USER", user.Username, $"Menambah user {user.FullName} ({user.Role})");

    return Results.Created($"/api/users/{user.Id}", user);
});

usersApi.MapPut("/{id:int}", async (int id, AppUser input, AppDbContext db, HttpContext ctx) =>
{
    var user = await db.AppUsers.FindAsync(id);
    if (user is null) return Results.NotFound();

    user.FullName = input.FullName;
    user.Role = input.Role;
    if (!string.IsNullOrWhiteSpace(input.Password))
    {
        user.Password = input.Password;
    }

    await db.SaveChangesAsync();

    var actor = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin";
    var actorRole = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Admin";
    await LogActionAsync(db, actor, actorRole, "EDIT_USER", user.Username, $"Memperbarui data user {user.Username} ({user.Role})");

    return Results.Ok(user);
});

usersApi.MapDelete("/{id:int}", async (int id, AppDbContext db, HttpContext ctx) =>
{
    var user = await db.AppUsers.FindAsync(id);
    if (user is null) return Results.NotFound();

    if (user.Role == "Admin" && await db.AppUsers.CountAsync(u => u.Role == "Admin") <= 1)
    {
        return Results.BadRequest(new { message = "Tidak dapat menghapus satu-satunya akun Admin." });
    }

    db.AppUsers.Remove(user);
    await db.SaveChangesAsync();

    var actor = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin";
    var actorRole = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Admin";
    await LogActionAsync(db, actor, actorRole, "HAPUS_USER", user.Username, $"Menghapus user {user.Username}");

    return Results.NoContent();
});

// Role Permissions
var rolesApi = app.MapGroup("/api/roles");

rolesApi.MapGet("/permissions", async (AppDbContext db) =>
    Results.Ok(await db.RolePermissions.ToListAsync()));

rolesApi.MapPost("/permissions", async (List<RolePermission> permissions, AppDbContext db, HttpContext ctx) =>
{
    foreach (var p in permissions)
    {
        var existing = await db.RolePermissions.FirstOrDefaultAsync(r => r.Role == p.Role && r.TabKey == p.TabKey);
        if (existing != null)
        {
            existing.CanAccess = p.CanAccess;
        }
        else
        {
            db.RolePermissions.Add(p);
        }
    }

    await db.SaveChangesAsync();

    var actor = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin";
    var actorRole = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Admin";
    await LogActionAsync(db, actor, actorRole, "UPDATE_PERMISSIONS", "RBAC", "Memperbarui konfigurasi hak akses tab role");

    return Results.Ok(await db.RolePermissions.ToListAsync());
});

// ==========================================
// 6. SYSTEM LOGS
// ==========================================
app.MapGet("/api/logs", async (AppDbContext db, string? search) =>
{
    var query = db.SystemLogs.AsQueryable();
    if (!string.IsNullOrWhiteSpace(search))
    {
        var s = search.ToLower();
        query = query.Where(l => l.Action.ToLower().Contains(s) || l.Entity.ToLower().Contains(s) || l.Username.ToLower().Contains(s) || l.Details.ToLower().Contains(s));
    }
    return Results.Ok(await query.OrderByDescending(l => l.CreatedAt).Take(200).ToListAsync());
});

// ==========================================
// 7. CONFIG & PUSHER NOTIFICATIONS
// ==========================================
var configApi = app.MapGroup("/api/config");

configApi.MapGet("/", async (AppDbContext db) =>
{
    var configs = await db.SystemConfigs.ToDictionaryAsync(c => c.Key, c => c.Value);
    return Results.Ok(configs);
});

configApi.MapPost("/", async (Dictionary<string, string> values, AppDbContext db, HttpContext ctx) =>
{
    foreach (var (k, v) in values)
    {
        var conf = await db.SystemConfigs.FirstOrDefaultAsync(c => c.Key == k);
        if (conf != null)
        {
            conf.Value = v;
        }
        else
        {
            db.SystemConfigs.Add(new SystemConfig { Key = k, Value = v });
        }
    }
    await db.SaveChangesAsync();

    var actor = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin";
    var actorRole = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Admin";
    await LogActionAsync(db, actor, actorRole, "UPDATE_CONFIG", "SystemConfig", "Memperbarui pengaturan sistem dan notifikasi");

    return Results.Ok(await db.SystemConfigs.ToDictionaryAsync(c => c.Key, c => c.Value));
});

configApi.MapPost("/test-pusher", async (AppDbContext db, IHttpClientFactory clientFactory, HttpContext ctx) =>
{
    var actor = ctx.Request.Headers["X-User"].FirstOrDefault() ?? "Admin";
    var actorRole = ctx.Request.Headers["X-Role"].FirstOrDefault() ?? "Admin";

    var success = await TriggerPusherAsync(clientFactory, db, "system-test", "test-ping", new
    {
        message = "Uji koneksi Pusher berhasil dari KasirPOS!",
        sender = actor,
        timestamp = DateTime.UtcNow
    });

    await LogActionAsync(db, actor, actorRole, "TEST_PUSHER", "PusherChannel", success ? "Uji notifikasi Pusher berhasil terkirim" : "Uji notifikasi Pusher gagal/kredensial belum lengkap");

    return Results.Ok(new
    {
        success,
        message = success ? "Notifikasi uji coba berhasil dikirim ke Pusher!" : "Gagal mengirim ke Pusher. Pastikan App ID, Key, Secret, Cluster terisi benar dan internet aktif."
    });
});

app.Run();

// ==========================================
// MODELS & DBCONTEXT
// ==========================================
public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<Product> Products => Set<Product>();
    public DbSet<Transaction> Transactions => Set<Transaction>();
    public DbSet<TransactionItem> TransactionItems => Set<TransactionItem>();
    public DbSet<AppUser> AppUsers => Set<AppUser>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<PurchaseOrder> PurchaseOrders => Set<PurchaseOrder>();
    public DbSet<PurchaseOrderItem> PurchaseOrderItems => Set<PurchaseOrderItem>();
    public DbSet<GoodsReceipt> GoodsReceipts => Set<GoodsReceipt>();
    public DbSet<GoodsReceiptItem> GoodsReceiptItems => Set<GoodsReceiptItem>();
    public DbSet<ReceiptRevision> ReceiptRevisions => Set<ReceiptRevision>();
    public DbSet<StockCard> StockCards => Set<StockCard>();
    public DbSet<StockOpname> StockOpnames => Set<StockOpname>();
    public DbSet<StockOpnameItem> StockOpnameItems => Set<StockOpnameItem>();
    public DbSet<SystemLog> SystemLogs => Set<SystemLog>();
    public DbSet<SystemConfig> SystemConfigs => Set<SystemConfig>();
}

public class Product
{
    public int Id { get; set; }
    public string Barcode { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public decimal Price { get; set; }
    public int Stock { get; set; }
}

public class Transaction
{
    public int Id { get; set; }
    public DateTime CreatedAt { get; set; }
    public decimal TotalAmount { get; set; }
    public decimal CashPaid { get; set; }
    public decimal ChangeAmount { get; set; }
    public List<TransactionItem> Items { get; set; } = [];
}

public class TransactionItem
{
    public int Id { get; set; }
    public int TransactionId { get; set; }
    public int ProductId { get; set; }
    public string ProductName { get; set; } = string.Empty;
    public int Quantity { get; set; }
    public decimal UnitPrice { get; set; }
    public decimal Subtotal { get; set; }
}

public class AppUser
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Role { get; set; } = "Kasir"; // Admin, Kasir, Gudang
}

public class RolePermission
{
    public int Id { get; set; }
    public string Role { get; set; } = string.Empty;
    public string TabKey { get; set; } = string.Empty;
    public bool CanAccess { get; set; } = true;
}

public class PurchaseOrder
{
    public int Id { get; set; }
    public string PoNumber { get; set; } = string.Empty;
    public string SupplierName { get; set; } = string.Empty;
    public string Status { get; set; } = "Diproses"; // Diproses, Sebagian, Selesai, Dibatalkan
    public DateTime CreatedAt { get; set; }
    public decimal TotalAmount { get; set; }
    public List<PurchaseOrderItem> Items { get; set; } = [];
}

public class PurchaseOrderItem
{
    public int Id { get; set; }
    public int PurchaseOrderId { get; set; }
    public int ProductId { get; set; }
    public string ProductName { get; set; } = string.Empty;
    public int QuantityOrdered { get; set; }
    public int QuantityReceived { get; set; }
    public decimal UnitPrice { get; set; }
}

public class GoodsReceipt
{
    public int Id { get; set; }
    public string ReceiptNumber { get; set; } = string.Empty;
    public int PurchaseOrderId { get; set; }
    public DateTime ReceivedAt { get; set; }
    public string ReceivedBy { get; set; } = string.Empty;
    public string Notes { get; set; } = string.Empty;
    public List<GoodsReceiptItem> Items { get; set; } = [];
    public List<ReceiptRevision> Revisions { get; set; } = [];
}

public class GoodsReceiptItem
{
    public int Id { get; set; }
    public int GoodsReceiptId { get; set; }
    public int ProductId { get; set; }
    public string ProductName { get; set; } = string.Empty;
    public int QuantityReceived { get; set; }
}

public class ReceiptRevision
{
    public int Id { get; set; }
    public int GoodsReceiptId { get; set; }
    public int ProductId { get; set; }
    public string ProductName { get; set; } = string.Empty;
    public DateTime RevisedAt { get; set; }
    public string RevisedBy { get; set; } = string.Empty;
    public int DeltaQuantity { get; set; }
    public string Reason { get; set; } = string.Empty;
}

public class StockCard
{
    public int Id { get; set; }
    public int ProductId { get; set; }
    public string ProductName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public string MovementType { get; set; } = string.Empty; // PENJUALAN, PENERIMAAN_PO, REVISI_PENERIMAAN, STOK_OPNAME, STOK_AWAL, PENYESUAIAN_MANUAL
    public string ReferenceNumber { get; set; } = string.Empty;
    public int QuantityChange { get; set; }
    public int StockAfter { get; set; }
    public string PerformedBy { get; set; } = string.Empty;
    public string Notes { get; set; } = string.Empty;
}

public class StockOpname
{
    public int Id { get; set; }
    public string OpnameNumber { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public string PerformedBy { get; set; } = string.Empty;
    public string Notes { get; set; } = string.Empty;
    public List<StockOpnameItem> Items { get; set; } = [];
}

public class StockOpnameItem
{
    public int Id { get; set; }
    public int StockOpnameId { get; set; }
    public int ProductId { get; set; }
    public string ProductName { get; set; } = string.Empty;
    public int SystemStock { get; set; }
    public int PhysicalStock { get; set; }
    public int Difference { get; set; }
}

public class SystemLog
{
    public int Id { get; set; }
    public DateTime CreatedAt { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Entity { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
}

public class SystemConfig
{
    public int Id { get; set; }
    public string Key { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}

// Request DTOs
public record LoginRequest(string Username, string Password);
public record CheckoutItemRequest(int ProductId, int Quantity);
public record CheckoutRequest(List<CheckoutItemRequest> Items, decimal CashPaid);

public record PoItemInput(int ProductId, string ProductName, int QuantityOrdered, decimal UnitPrice);
public record CreatePoRequest(string SupplierName, List<PoItemInput> Items);

public record ReceiptItemInput(int ProductId, int QuantityReceived);
public record CreateReceiptRequest(int PurchaseOrderId, string? Notes, List<ReceiptItemInput> Items);

public record ReviseReceiptRequest(int ProductId, int DeltaQuantity, string Reason);

public record OpnameItemInput(int ProductId, int PhysicalStock);
public record CreateOpnameRequest(string? Notes, List<OpnameItemInput> Items);

// Database Schema Initializer
public static class DbInitializer
{
    public static async Task InitAsync(AppDbContext db)
    {
        // ponytail: Execute raw DDL to guarantee schema creation in existing PostgreSQL database without EF migrations. Ceiling: multi-node distributed schema versioning.
        const string ddl = """
        CREATE TABLE IF NOT EXISTS "Products" (
            "Id" SERIAL PRIMARY KEY,
            "Barcode" TEXT NOT NULL DEFAULT '',
            "Name" TEXT NOT NULL DEFAULT '',
            "Price" NUMERIC NOT NULL DEFAULT 0,
            "Stock" INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS "Transactions" (
            "Id" SERIAL PRIMARY KEY,
            "CreatedAt" TIMESTAMPTZ NOT NULL,
            "TotalAmount" NUMERIC NOT NULL DEFAULT 0,
            "CashPaid" NUMERIC NOT NULL DEFAULT 0,
            "ChangeAmount" NUMERIC NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS "TransactionItems" (
            "Id" SERIAL PRIMARY KEY,
            "TransactionId" INTEGER NOT NULL REFERENCES "Transactions"("Id") ON DELETE CASCADE,
            "ProductId" INTEGER NOT NULL,
            "ProductName" TEXT NOT NULL DEFAULT '',
            "Quantity" INTEGER NOT NULL DEFAULT 0,
            "UnitPrice" NUMERIC NOT NULL DEFAULT 0,
            "Subtotal" NUMERIC NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS "AppUsers" (
            "Id" SERIAL PRIMARY KEY,
            "Username" TEXT NOT NULL UNIQUE,
            "Password" TEXT NOT NULL DEFAULT '',
            "FullName" TEXT NOT NULL DEFAULT '',
            "Role" TEXT NOT NULL DEFAULT 'Kasir'
        );

        CREATE TABLE IF NOT EXISTS "RolePermissions" (
            "Id" SERIAL PRIMARY KEY,
            "Role" TEXT NOT NULL,
            "TabKey" TEXT NOT NULL,
            "CanAccess" BOOLEAN NOT NULL DEFAULT TRUE
        );

        CREATE TABLE IF NOT EXISTS "PurchaseOrders" (
            "Id" SERIAL PRIMARY KEY,
            "PoNumber" TEXT NOT NULL,
            "SupplierName" TEXT NOT NULL DEFAULT '',
            "Status" TEXT NOT NULL DEFAULT 'Diproses',
            "CreatedAt" TIMESTAMPTZ NOT NULL,
            "TotalAmount" NUMERIC NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS "PurchaseOrderItems" (
            "Id" SERIAL PRIMARY KEY,
            "PurchaseOrderId" INTEGER NOT NULL REFERENCES "PurchaseOrders"("Id") ON DELETE CASCADE,
            "ProductId" INTEGER NOT NULL,
            "ProductName" TEXT NOT NULL DEFAULT '',
            "QuantityOrdered" INTEGER NOT NULL DEFAULT 0,
            "QuantityReceived" INTEGER NOT NULL DEFAULT 0,
            "UnitPrice" NUMERIC NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS "GoodsReceipts" (
            "Id" SERIAL PRIMARY KEY,
            "ReceiptNumber" TEXT NOT NULL,
            "PurchaseOrderId" INTEGER NOT NULL,
            "ReceivedAt" TIMESTAMPTZ NOT NULL,
            "ReceivedBy" TEXT NOT NULL DEFAULT '',
            "Notes" TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS "GoodsReceiptItems" (
            "Id" SERIAL PRIMARY KEY,
            "GoodsReceiptId" INTEGER NOT NULL REFERENCES "GoodsReceipts"("Id") ON DELETE CASCADE,
            "ProductId" INTEGER NOT NULL,
            "ProductName" TEXT NOT NULL DEFAULT '',
            "QuantityReceived" INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS "ReceiptRevisions" (
            "Id" SERIAL PRIMARY KEY,
            "GoodsReceiptId" INTEGER NOT NULL REFERENCES "GoodsReceipts"("Id") ON DELETE CASCADE,
            "ProductId" INTEGER NOT NULL,
            "ProductName" TEXT NOT NULL DEFAULT '',
            "RevisedAt" TIMESTAMPTZ NOT NULL,
            "RevisedBy" TEXT NOT NULL DEFAULT '',
            "DeltaQuantity" INTEGER NOT NULL DEFAULT 0,
            "Reason" TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS "StockCards" (
            "Id" SERIAL PRIMARY KEY,
            "ProductId" INTEGER NOT NULL,
            "ProductName" TEXT NOT NULL DEFAULT '',
            "CreatedAt" TIMESTAMPTZ NOT NULL,
            "MovementType" TEXT NOT NULL DEFAULT '',
            "ReferenceNumber" TEXT NOT NULL DEFAULT '',
            "QuantityChange" INTEGER NOT NULL DEFAULT 0,
            "StockAfter" INTEGER NOT NULL DEFAULT 0,
            "PerformedBy" TEXT NOT NULL DEFAULT '',
            "Notes" TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS "StockOpnames" (
            "Id" SERIAL PRIMARY KEY,
            "OpnameNumber" TEXT NOT NULL,
            "CreatedAt" TIMESTAMPTZ NOT NULL,
            "PerformedBy" TEXT NOT NULL DEFAULT '',
            "Notes" TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS "StockOpnameItems" (
            "Id" SERIAL PRIMARY KEY,
            "StockOpnameId" INTEGER NOT NULL REFERENCES "StockOpnames"("Id") ON DELETE CASCADE,
            "ProductId" INTEGER NOT NULL,
            "ProductName" TEXT NOT NULL DEFAULT '',
            "SystemStock" INTEGER NOT NULL DEFAULT 0,
            "PhysicalStock" INTEGER NOT NULL DEFAULT 0,
            "Difference" INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS "SystemLogs" (
            "Id" SERIAL PRIMARY KEY,
            "CreatedAt" TIMESTAMPTZ NOT NULL,
            "Username" TEXT NOT NULL DEFAULT '',
            "Role" TEXT NOT NULL DEFAULT '',
            "Action" TEXT NOT NULL DEFAULT '',
            "Entity" TEXT NOT NULL DEFAULT '',
            "Details" TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS "SystemConfigs" (
            "Id" SERIAL PRIMARY KEY,
            "Key" TEXT NOT NULL UNIQUE,
            "Value" TEXT NOT NULL DEFAULT ''
        );
        """;

        await db.Database.ExecuteSqlRawAsync(ddl);

        // Seed Users
        if (!await db.AppUsers.AnyAsync())
        {
            db.AppUsers.AddRange(
                new AppUser { Username = "admin", FullName = "Administrator Utama", Password = "admin", Role = "Admin" },
                new AppUser { Username = "kasir", FullName = "Staf Kasir", Password = "kasir", Role = "Kasir" },
                new AppUser { Username = "gudang", FullName = "Staf Gudang", Password = "gudang", Role = "Gudang" }
            );
            await db.SaveChangesAsync();
        }

        // Seed Role Permissions
        if (!await db.RolePermissions.AnyAsync())
        {
            var tabs = new[] { "pos", "products", "history", "warehouse", "reports", "users", "logs", "config" };
            var list = new List<RolePermission>();

            // Admin: All
            foreach (var tab in tabs) list.Add(new RolePermission { Role = "Admin", TabKey = tab, CanAccess = true });

            // Kasir: POS, History, Catalog
            list.Add(new RolePermission { Role = "Kasir", TabKey = "pos", CanAccess = true });
            list.Add(new RolePermission { Role = "Kasir", TabKey = "history", CanAccess = true });
            list.Add(new RolePermission { Role = "Kasir", TabKey = "products", CanAccess = false });
            list.Add(new RolePermission { Role = "Kasir", TabKey = "warehouse", CanAccess = false });
            list.Add(new RolePermission { Role = "Kasir", TabKey = "reports", CanAccess = false });
            list.Add(new RolePermission { Role = "Kasir", TabKey = "users", CanAccess = false });
            list.Add(new RolePermission { Role = "Kasir", TabKey = "logs", CanAccess = false });
            list.Add(new RolePermission { Role = "Kasir", TabKey = "config", CanAccess = false });

            // Gudang: Warehouse, Products, Logs
            list.Add(new RolePermission { Role = "Gudang", TabKey = "pos", CanAccess = false });
            list.Add(new RolePermission { Role = "Gudang", TabKey = "history", CanAccess = false });
            list.Add(new RolePermission { Role = "Gudang", TabKey = "products", CanAccess = true });
            list.Add(new RolePermission { Role = "Gudang", TabKey = "warehouse", CanAccess = true });
            list.Add(new RolePermission { Role = "Gudang", TabKey = "reports", CanAccess = false });
            list.Add(new RolePermission { Role = "Gudang", TabKey = "users", CanAccess = false });
            list.Add(new RolePermission { Role = "Gudang", TabKey = "logs", CanAccess = true });
            list.Add(new RolePermission { Role = "Gudang", TabKey = "config", CanAccess = false });

            db.RolePermissions.AddRange(list);
            await db.SaveChangesAsync();
        }

        // Seed Initial Configs
        var defaultConfigs = new Dictionary<string, string>
        {
            ["store_name"] = "KasirPOS Indonesia",
            ["store_address"] = "Pusat Operasional",
            ["store_phone"] = "0812-3456-7890",
            ["pusher_enabled"] = "false",
            ["pusher_app_id"] = "",
            ["pusher_key"] = "",
            ["pusher_secret"] = "",
            ["pusher_cluster"] = "ap1"
        };

        foreach (var (k, v) in defaultConfigs)
        {
            if (!await db.SystemConfigs.AnyAsync(c => c.Key == k))
            {
                db.SystemConfigs.Add(new SystemConfig { Key = k, Value = v });
            }
        }
        await db.SaveChangesAsync();
    }
}
