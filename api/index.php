<?php
declare(strict_types=1);
require __DIR__ . "/bootstrap.php";

$method = strtoupper($_SERVER["REQUEST_METHOD"] ?? "GET");
$route = trim((string) ($_GET["route"] ?? ""), "/");
$pdo = db();

try {
    /* Authentication */
    if ($route === "auth/me" && $method === "GET") {
        $user = current_user();
        json_response(["ok" => true, "user" => $user, "csrf" => csrf_token()]);
    }
    if ($route === "auth/login" && $method === "POST") {
        $data = input();
        $email = strtolower(value($data, "email", 190));
        $password = (string) ($data["password"] ?? "");
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === "") {
            fail("Enter a valid email address and password.", 422);
        }
        $stmt = $pdo->prepare(
            "SELECT u.id, u.full_name, u.email, u.phone, u.password_hash, u.account_status, r.name AS role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.email=? LIMIT 1",
        );
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if (!$user || !password_verify($password, $user["password_hash"])) {
            fail("Incorrect email address or password.", 401);
        }
        if ($user["account_status"] !== "active") {
            fail("This account is not active yet.", 403);
        }
        session_regenerate_id(true);
        $_SESSION["user_id"] = (int) $user["id"];
        $_SESSION["csrf"] = bin2hex(random_bytes(32));
        $pdo->prepare(
            "UPDATE users SET last_login_at=NOW() WHERE id=?",
        )->execute([$user["id"]]);
        audit(
            (int) $user["id"],
            "login",
            "user",
            (int) $user["id"],
            "Successful sign in.",
        );
        unset($user["password_hash"]);
        json_response([
            "ok" => true,
            "user" => $user,
            "csrf" => $_SESSION["csrf"],
        ]);
    }
    if ($route === "auth/register" && $method === "POST") {
        $data = input();
        $first = value($data, "first_name", 60);
        $last = value($data, "last_name", 60);
        $email = strtolower(value($data, "email", 190));
        $phone = value($data, "phone", 30);
        $password = (string) ($data["password"] ?? "");
        $make = value($data, "vehicle", 100);
        $plate = strtoupper(value($data, "plate", 40));
        if (
            $first === "" ||
            $last === "" ||
            !filter_var($email, FILTER_VALIDATE_EMAIL) ||
            $phone === "" ||
            $make === "" ||
            $plate === ""
        ) {
            fail(
                "Please complete all required account and vehicle fields.",
                422,
            );
        }
        if (mb_strlen($password) < 8) {
            fail("Password must be at least 8 characters.", 422);
        }
        $year = filter_var($data["year"] ?? null, FILTER_VALIDATE_INT, [
            "options" => [
                "min_range" => 1990,
                "max_range" => (int) date("Y") + 1,
            ],
        ]);
        if ($year === false) {
            fail("Enter a valid vehicle year.", 422);
        }
        $pdo->beginTransaction();
        try {
            $roleId = first_id("SELECT id FROM roles WHERE name='driver'");
            $stmt = $pdo->prepare(
                'INSERT INTO users (role_id,full_name,email,phone,password_hash,account_status,email_verified_at) VALUES (?,?,?,?,?,\'active\',NOW())',
            );
            $stmt->execute([
                $roleId,
                "$first $last",
                $email,
                $phone,
                password_hash($password, PASSWORD_DEFAULT),
            ]);
            $userId = (int) $pdo->lastInsertId();
            $pdo->prepare(
                "INSERT INTO driver_profiles (user_id, city, receive_updates) VALUES (?, ?, ?)",
            )->execute([$userId, "Dhaka", !empty($data["updates"]) ? 1 : 0]);
            $pdo->prepare(
                "INSERT INTO vehicles (driver_user_id,registration_number,make_model,vehicle_year,vehicle_type,is_primary) VALUES (?,?,?,?,?,1)",
            )->execute([
                $userId,
                $plate,
                $make,
                $year,
                normalized_vehicle_type((string) ($data["type"] ?? "sedan")),
            ]);
            $pdo->commit();
        } catch (Throwable $exception) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if (
                $exception instanceof PDOException &&
                $exception->getCode() === "23000"
            ) {
                fail(
                    "That email address or vehicle registration is already registered.",
                    409,
                );
            }
            throw $exception;
        }
        session_regenerate_id(true);
        $_SESSION["user_id"] = $userId;
        $_SESSION["csrf"] = bin2hex(random_bytes(32));
        audit($userId, "register", "user", $userId, "Driver account created.");
        json_response(
            [
                "ok" => true,
                "user" => [
                    "id" => $userId,
                    "full_name" => "$first $last",
                    "email" => $email,
                    "phone" => $phone,
                    "role" => "driver",
                ],
                "csrf" => $_SESSION["csrf"],
            ],
            201,
        );
    }
    if ($route === "auth/logout" && $method === "POST") {
        require_login();
        require_csrf();
        $id = (int) $_SESSION["user_id"];
        audit($id, "logout", "user", $id, "Signed out.");
        $_SESSION = [];
        session_destroy();
        json_response(["ok" => true]);
    }

    if ($route === "notifications" && $method === "GET") {
        $user = require_login();
        $stmt = $pdo->prepare(
            "SELECT id,type,title,body,link,read_at,created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC,id DESC LIMIT 20",
        );
        $stmt->execute([(int) $user["id"]]);
        $items = $stmt->fetchAll();
        json_response([
            "ok" => true,
            "notifications" => $items,
            "unread_count" => count(
                array_filter($items, fn($item) => empty($item["read_at"])),
            ),
        ]);
    }
    if ($route === "notifications/read" && $method === "POST") {
        $user = require_login();
        require_csrf();
        $pdo->prepare(
            "UPDATE notifications SET read_at=NOW() WHERE user_id=? AND read_at IS NULL",
        )->execute([(int) $user["id"]]);
        json_response(["ok" => true]);
    }
    if (
        preg_match('#^notifications/(\d+)/read$#', $route, $match) &&
        $method === "POST"
    ) {
        $user = require_login();
        require_csrf();
        $pdo->prepare(
            "UPDATE notifications SET read_at=NOW() WHERE id=? AND user_id=? AND read_at IS NULL",
        )->execute([(int) $match[1], (int) $user["id"]]);
        json_response(["ok" => true]);
    }

    /* Public data */
    if ($route === "public/locations" && $method === "GET") {
        $stmt = $pdo->query(
            "SELECT l.id,l.name,l.address,l.area,l.city,l.base_hourly_rate,l.total_capacity,l.status, COUNT(ps.id) AS spaces_total, SUM(ps.status='available') AS available_spaces, ROUND(AVG(r.rating),1) AS rating FROM parking_locations l LEFT JOIN parking_zones z ON z.location_id=l.id LEFT JOIN parking_spaces ps ON ps.zone_id=z.id LEFT JOIN reviews r ON r.location_id=l.id AND r.is_published=1 WHERE l.status='operational' GROUP BY l.id ORDER BY l.base_hourly_rate ASC",
        );
        json_response(["ok" => true, "locations" => $stmt->fetchAll()]);
    }
    if ($route === "public/support" && $method === "POST") {
        $data = input();
        $name = value($data, "name", 120);
        $email = strtolower(value($data, "email", 190));
        $subject = value($data, "subject", 150);
        $message = value($data, "message", 2000);
        if (
            $name === "" ||
            !filter_var($email, FILTER_VALIDATE_EMAIL) ||
            $subject === "" ||
            $message === ""
        ) {
            fail("Please complete all support fields.", 422);
        }
        $code = "SUP-" . strtoupper(bin2hex(random_bytes(3)));
        $user = current_user();
        $stmt = $pdo->prepare(
            "INSERT INTO support_tickets(ticket_code,user_id,name,email,subject,message) VALUES(?,?,?,?,?,?)",
        );
        $stmt->execute([
            $code,
            $user["id"] ?? null,
            $name,
            $email,
            $subject,
            $message,
        ]);
        json_response(["ok" => true, "ticket_code" => $code], 201);
    }

    /* Administrator */
    if ($route === "admin/profile" && $method === "GET") {
        $admin = require_login(["admin"]);
        $stmt = $pdo->prepare(
            "SELECT id, full_name, email, phone FROM users WHERE id=? LIMIT 1",
        );
        $stmt->execute([(int) $admin["id"]]);
        json_response(["ok" => true, "profile" => $stmt->fetch()]);
    }
    if ($route === "admin/profile" && $method === "PUT") {
        $admin = require_login(["admin"]);
        require_csrf();
        $data = input();
        $name = value($data, "name", 120);
        $phone = value($data, "phone", 30);
        if ($name === "") {
            fail("Full name is required.", 422);
        }
        $stmt = $pdo->prepare(
            "UPDATE users SET full_name=?, phone=? WHERE id=?",
        );
        $stmt->execute([
            $name,
            $phone !== "" ? $phone : null,
            (int) $admin["id"],
        ]);
        audit(
            (int) $admin["id"],
            "update",
            "profile",
            (int) $admin["id"],
            "Updated administrator profile.",
        );
        json_response(["ok" => true]);
    }
    if ($route === "admin/dashboard" && $method === "GET") {
        require_login(["admin"]);
        $metrics = [
            "drivers" => (int) $pdo
                ->query(
                    "SELECT COUNT(*) FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name='driver' AND u.account_status='active'",
                )
                ->fetchColumn(),
            "managers" => (int) $pdo
                ->query(
                    "SELECT COUNT(*) FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name='manager' AND u.account_status='active'",
                )
                ->fetchColumn(),
            "locations" => (int) $pdo
                ->query(
                    "SELECT COUNT(*) FROM parking_locations WHERE status='operational'",
                )
                ->fetchColumn(),
            "reservations" => (int) $pdo
                ->query(
                    "SELECT COUNT(*) FROM reservations WHERE DATE(created_at)=CURDATE()",
                )
                ->fetchColumn(),
            "revenue" => (float) $pdo
                ->query(
                    "SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='paid' AND DATE(paid_at)=CURDATE()",
                )
                ->fetchColumn(),
            "occupied_spaces" => (int) $pdo
                ->query(
                    "SELECT COUNT(*) FROM parking_spaces WHERE status='occupied'",
                )
                ->fetchColumn(),
            "spaces" => (int) $pdo
                ->query("SELECT COUNT(*) FROM parking_spaces")
                ->fetchColumn(),
        ];
        $recent = $pdo
            ->query(
                "SELECT r.id,r.reservation_code,r.starts_at,r.ends_at,r.status,r.total_amount,u.full_name,v.registration_number,l.name AS location_name FROM reservations r JOIN users u ON u.id=r.driver_user_id JOIN vehicles v ON v.id=r.vehicle_id JOIN parking_locations l ON l.id=r.location_id ORDER BY r.created_at DESC LIMIT 8",
            )
            ->fetchAll();
        $utilization = $pdo
            ->query(
                "SELECT status,COUNT(*) AS total FROM parking_spaces GROUP BY status",
            )
            ->fetchAll();
        json_response([
            "ok" => true,
            "metrics" => $metrics,
            "recent_reservations" => $recent,
            "utilization" => $utilization,
        ]);
    }
    if (
        preg_match('#^admin/reservations/(\d+)$#', $route, $match) &&
        $method === "GET"
    ) {
        require_login(["admin"]);
        $stmt = $pdo->prepare(
            "SELECT r.id,r.reservation_code,r.status,r.starts_at,r.ends_at,r.actual_check_in_at,r.actual_check_out_at,r.hourly_rate,r.service_fee,r.discount_amount,r.total_amount,r.notes,r.created_at,r.updated_at,u.full_name AS driver_name,u.email AS driver_email,u.phone AS driver_phone,v.registration_number,v.make_model,v.vehicle_type,v.color,l.name AS location_name,l.address AS location_address,ps.space_code,z.code AS zone_code,p.payment_reference,p.amount AS payment_amount,p.method AS payment_method,p.status AS payment_status,p.paid_at FROM reservations r JOIN users u ON u.id=r.driver_user_id JOIN vehicles v ON v.id=r.vehicle_id JOIN parking_locations l ON l.id=r.location_id LEFT JOIN parking_spaces ps ON ps.id=r.space_id LEFT JOIN parking_zones z ON z.id=ps.zone_id LEFT JOIN payments p ON p.id=(SELECT id FROM payments WHERE reservation_id=r.id ORDER BY id DESC LIMIT 1) WHERE r.id=? LIMIT 1",
        );
        $stmt->execute([(int) $match[1]]);
        $reservation = $stmt->fetch();
        if (!$reservation) {
            fail("Reservation not found.", 404);
        }
        json_response(["ok" => true, "reservation" => $reservation]);
    }
    if ($route === "admin/analytics" && $method === "GET") {
        require_login(["admin"]);
        $days = (int) ($_GET["days"] ?? 30);
        if (!in_array($days, [7, 30, 365], true)) {
            $days = 30;
        }
        $from = date("Y-m-d 00:00:00", strtotime("-" . ($days - 1) . " days"));
        $byLocation = $pdo->prepare(
            "SELECT l.id,l.name,(SELECT COUNT(*) FROM reservations r WHERE r.location_id=l.id AND r.starts_at>=?) AS reservations,COALESCE((SELECT SUM(p.amount) FROM payments p JOIN reservations r ON r.id=p.reservation_id WHERE r.location_id=l.id AND r.starts_at>=? AND p.status='paid'),0) AS revenue,(SELECT COUNT(*) FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=l.id) AS spaces,(SELECT COUNT(*) FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=l.id AND ps.status='occupied') AS occupied FROM parking_locations l ORDER BY revenue DESC,l.name",
        );
        $byLocation->execute([$from, $from]);
        $trend = $pdo->prepare(
            "SELECT DATE(r.starts_at) AS day,COUNT(DISTINCT r.id) AS reservations,COALESCE(SUM(p.amount),0) AS revenue FROM reservations r LEFT JOIN payments p ON p.reservation_id=r.id AND p.status='paid' WHERE r.starts_at>=? GROUP BY DATE(r.starts_at) ORDER BY day",
        );
        $trend->execute([$from]);
        $previousFrom = date(
            "Y-m-d 00:00:00",
            strtotime("-" . ($days * 2 - 1) . " days"),
        );
        $previousUntil = date(
            "Y-m-d 00:00:00",
            strtotime("-" . $days . " days"),
        );
        $previousTrend = $pdo->prepare(
            "SELECT DATE(r.starts_at) AS day,COUNT(DISTINCT r.id) AS reservations,COALESCE(SUM(p.amount),0) AS revenue FROM reservations r LEFT JOIN payments p ON p.reservation_id=r.id AND p.status='paid' WHERE r.starts_at>=? AND r.starts_at<? GROUP BY DATE(r.starts_at) ORDER BY day",
        );
        $previousTrend->execute([$previousFrom, $previousUntil]);
        json_response([
            "ok" => true,
            "days" => $days,
            "period_start" => $from,
            "period_end" => date("Y-m-d"),
            "locations" => $byLocation->fetchAll(),
            "trend" => $trend->fetchAll(),
            "previous_trend" => $previousTrend->fetchAll(),
        ]);
    }
    if ($route === "admin/managers" && $method === "GET") {
        require_login(["admin"]);
        $sql =
            "SELECT u.id,u.full_name,u.email,u.phone,u.account_status,mp.employee_code,COALESCE(NULLIF(GROUP_CONCAT(DISTINCT CONCAT(DATE_FORMAT(a.shift_start,'%H:%i'),'–',DATE_FORMAT(a.shift_end,'%H:%i')) ORDER BY a.is_primary DESC SEPARATOR ', '),''),mp.shift_name,'—') AS shift_name,MIN(a.shift_start) AS shift_start,MIN(a.shift_end) AS shift_end,GROUP_CONCAT(l.name ORDER BY l.name SEPARATOR ', ') AS locations FROM users u JOIN roles r ON r.id=u.role_id LEFT JOIN manager_profiles mp ON mp.user_id=u.id LEFT JOIN manager_location_assignments a ON a.manager_user_id=u.id LEFT JOIN parking_locations l ON l.id=a.location_id WHERE r.name='manager' GROUP BY u.id ORDER BY u.created_at DESC";
        json_response([
            "ok" => true,
            "managers" => $pdo->query($sql)->fetchAll(),
        ]);
    }
    if ($route === "admin/managers" && $method === "POST") {
        $admin = require_login(["admin"]);
        require_csrf();
        $data = input();
        $name = value($data, "name", 120);
        $email = strtolower(value($data, "email", 190));
        $phone = value($data, "phone", 30);
        $password = (string) ($data["password"] ?? "Manager2026!");
        $locationId = (int) ($data["location_id"] ?? 0);
        $start = value($data, "shift_start", 8);
        $end = value($data, "shift_end", 8);
        if (
            $name === "" ||
            !filter_var($email, FILTER_VALIDATE_EMAIL) ||
            $locationId < 1 ||
            mb_strlen($password) < 8
        ) {
            fail(
                "Name, valid email, location, and an 8-character password are required.",
                422,
            );
        }
        $pdo->beginTransaction();
        try {
            $roleId = first_id("SELECT id FROM roles WHERE name='manager'");
            $stmt = $pdo->prepare(
                "INSERT INTO users(role_id,full_name,email,phone,password_hash,account_status,email_verified_at) VALUES(?,?,?,?,?,'pending',NOW())",
            );
            $stmt->execute([
                $roleId,
                $name,
                $email,
                $phone,
                password_hash($password, PASSWORD_DEFAULT),
            ]);
            $id = (int) $pdo->lastInsertId();
            $pdo->prepare(
                "INSERT INTO manager_profiles(user_id,employee_code,shift_name) VALUES(?,?,?)",
            )->execute([
                $id,
                "PF-MGR-" . str_pad((string) $id, 4, "0", STR_PAD_LEFT),
                "Assigned shift",
            ]);
            $pdo->prepare(
                "INSERT INTO manager_location_assignments(manager_user_id,location_id,shift_start,shift_end,is_primary) VALUES(?,?,?,?,1)",
            )->execute([$id, $locationId, $start ?: null, $end ?: null]);
            $pdo->commit();
            audit(
                (int) $admin["id"],
                "create",
                "manager",
                $id,
                "Created $name.",
            );
        } catch (Throwable $exception) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if (
                $exception instanceof PDOException &&
                $exception->getCode() === "23000"
            ) {
                fail("That manager email already exists.", 409);
            }
            throw $exception;
        }
        json_response(["ok" => true, "id" => $id], 201);
    }
    if (
        preg_match('#^admin/managers/(\d+)$#', $route, $match) &&
        $method === "DELETE"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $id = (int) $match[1];
        if ($id === (int) $admin["id"]) {
            fail("You cannot remove your own account.", 422);
        }
        $stmt = $pdo->prepare(
            "UPDATE users SET account_status='suspended' WHERE id=? AND role_id=(SELECT id FROM roles WHERE name='manager')",
        );
        $stmt->execute([$id]);
        if (!$stmt->rowCount()) {
            fail("Manager not found.", 404);
        }
        audit(
            (int) $admin["id"],
            "suspend",
            "manager",
            $id,
            "Manager access removed.",
        );
        json_response(["ok" => true]);
    }
    if (
        preg_match('#^admin/managers/(\d+)/activate$#', $route, $match) &&
        $method === "POST"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $id = (int) $match[1];
        $stmt = $pdo->prepare(
            "UPDATE users SET account_status='active' WHERE id=? AND role_id=(SELECT id FROM roles WHERE name='manager') AND account_status='suspended'",
        );
        $stmt->execute([$id]);
        if (!$stmt->rowCount()) {
            fail("Only a suspended manager account can be reactivated.", 422);
        }
        audit(
            (int) $admin["id"],
            "reactivate",
            "manager",
            $id,
            "Manager access restored.",
        );
        json_response(["ok" => true, "status" => "active"]);
    }
    if (
        preg_match('#^admin/managers/(\d+)$#', $route, $match) &&
        $method === "PUT"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $id = (int) $match[1];
        $data = input();
        $name = value($data, "name", 120);
        $phone = value($data, "phone", 30);
        $locationId = (int) ($data["location_id"] ?? 0);
        $start = value($data, "shift_start", 8);
        $end = value($data, "shift_end", 8);
        if ($name === "" || $locationId < 1) {
            fail("Name and assigned location are required.", 422);
        }
        $check = $pdo->prepare(
            "SELECT id FROM users WHERE id=? AND role_id=(SELECT id FROM roles WHERE name='manager')",
        );
        $check->execute([$id]);
        if (!$check->fetch()) {
            fail("Manager not found.", 404);
        }
        $pdo->beginTransaction();
        try {
            $pdo->prepare(
                "UPDATE users SET full_name=?,phone=? WHERE id=?",
            )->execute([$name, $phone ?: null, $id]);
            $pdo->prepare(
                "DELETE FROM manager_location_assignments WHERE manager_user_id=?",
            )->execute([$id]);
            $pdo->prepare(
                "INSERT INTO manager_location_assignments(manager_user_id,location_id,shift_start,shift_end,is_primary) VALUES(?,?,?,?,1)",
            )->execute([$id, $locationId, $start ?: null, $end ?: null]);
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        audit((int) $admin["id"], "update", "manager", $id, $name);
        json_response(["ok" => true]);
    }
    if ($route === "admin/manager-approvals" && $method === "GET") {
        require_login(["admin"]);
        $stmt = $pdo->query(
            "SELECT u.id,u.full_name,u.email,u.phone,u.account_status,u.created_at,mp.employee_code,GROUP_CONCAT(l.name ORDER BY l.name SEPARATOR ', ') AS locations FROM users u JOIN roles r ON r.id=u.role_id LEFT JOIN manager_profiles mp ON mp.user_id=u.id LEFT JOIN manager_location_assignments a ON a.manager_user_id=u.id LEFT JOIN parking_locations l ON l.id=a.location_id WHERE r.name='manager' AND u.account_status IN ('pending','rejected') GROUP BY u.id ORDER BY u.created_at ASC",
        );
        json_response(["ok" => true, "applications" => $stmt->fetchAll()]);
    }
    if (
        preg_match('#^admin/manager-approvals/(\d+)$#', $route, $match) &&
        $method === "POST"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $id = (int) $match[1];
        $data = input();
        $decision = value($data, "decision", 12);
        if (!in_array($decision, ["approve", "reject"], true)) {
            fail("Invalid approval decision.", 422);
        }
        $status = $decision === "approve" ? "active" : "rejected";
        $stmt = $pdo->prepare(
            "UPDATE users u JOIN roles r ON r.id=u.role_id SET u.account_status=? WHERE u.id=? AND r.name='manager' AND u.account_status='pending'",
        );
        $stmt->execute([$status, $id]);
        if (!$stmt->rowCount()) {
            fail("Pending manager application not found.", 404);
        }
        if ($decision === "approve") {
            $pdo->prepare(
                "UPDATE manager_profiles SET approved_by_user_id=?,approved_at=NOW() WHERE user_id=?",
            )->execute([(int) $admin["id"], $id]);
        }
        audit(
            (int) $admin["id"],
            $decision,
            "manager",
            $id,
            "Manager application reviewed.",
        );
        json_response(["ok" => true, "status" => $status]);
    }
    if ($route === "admin/locations" && $method === "GET") {
        require_login(["admin"]);
        $sql =
            "SELECT l.*, COUNT(DISTINCT ps.id) spaces_total, COALESCE(SUM(ps.status='occupied'),0) occupied_spaces, GROUP_CONCAT(DISTINCT u.full_name ORDER BY u.full_name SEPARATOR ', ') AS managers FROM parking_locations l LEFT JOIN parking_zones z ON z.location_id=l.id LEFT JOIN parking_spaces ps ON ps.zone_id=z.id LEFT JOIN manager_location_assignments a ON a.location_id=l.id LEFT JOIN users u ON u.id=a.manager_user_id GROUP BY l.id ORDER BY l.name";
        json_response([
            "ok" => true,
            "locations" => $pdo->query($sql)->fetchAll(),
        ]);
    }
    if ($route === "admin/locations" && $method === "POST") {
        $admin = require_login(["admin"]);
        require_csrf();
        $data = input();
        $name = value($data, "name", 150);
        $address = value($data, "address", 255);
        $area = value($data, "area", 100);
        $rate = (float) ($data["rate"] ?? 0);
        $capacity = (int) ($data["capacity"] ?? 0);
        $managerId = (int) ($data["manager_user_id"] ?? 0);
        if (
            $name === "" ||
            $address === "" ||
            $area === "" ||
            $rate <= 0 ||
            $capacity < 1 ||
            $capacity > 1000
        ) {
            fail(
                "Name, address, a positive rate, and a capacity from 1 to 1000 are required.",
                422,
            );
        }
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare(
                "INSERT INTO parking_locations(name,address,area,base_hourly_rate,total_capacity) VALUES(?,?,?,?,0)",
            );
            $stmt->execute([$name, $address, $area, $rate]);
            $id = (int) $pdo->lastInsertId();
            synchronize_location_capacity($pdo, $id, $capacity);
            if ($managerId) {
                $pdo->prepare(
                    "UPDATE manager_location_assignments SET is_primary=0 WHERE manager_user_id=?",
                )->execute([$managerId]);
                $pdo->prepare(
                    "INSERT INTO manager_location_assignments(manager_user_id,location_id,is_primary) VALUES(?,?,1)",
                )->execute([$managerId, $id]);
                ensure_manager_primary_assignment($pdo, $managerId);
            }
            $pdo->commit();
            audit((int) $admin["id"], "create", "parking_location", $id, $name);
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        json_response(["ok" => true, "id" => $id], 201);
    }
    if (
        preg_match('#^admin/locations/(\d+)/zones$#', $route, $match) &&
        $method === "GET"
    ) {
        require_login(["admin"]);
        $locationId = (int) $match[1];
        $stmt = $pdo->prepare(
            "SELECT z.id,z.name,z.code,z.floor_label,z.description,COUNT(ps.id) AS spaces_total,SUM(ps.status='available') AS available_spaces FROM parking_zones z LEFT JOIN parking_spaces ps ON ps.zone_id=z.id WHERE z.location_id=? GROUP BY z.id ORDER BY z.code,z.id",
        );
        $stmt->execute([$locationId]);
        json_response(["ok" => true, "zones" => $stmt->fetchAll()]);
    }
    if (
        preg_match('#^admin/locations/(\d+)/zones$#', $route, $match) &&
        $method === "POST"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $locationId = (int) $match[1];
        $data = input();
        $name = value($data, "name", 100);
        $code = strtoupper(value($data, "code", 20));
        $floor = value($data, "floor_label", 50);
        if ($name === "" || $code === "") {
            fail("Zone name and zone code are required.", 422);
        }
        if (!first_id("SELECT id FROM parking_locations WHERE id=?", [$locationId])) {
            fail("Parking location not found.", 404);
        }
        try {
            $stmt = $pdo->prepare(
                "INSERT INTO parking_zones(location_id,name,code,floor_label) VALUES(?,?,?,?)",
            );
            $stmt->execute([$locationId, $name, $code, $floor ?: null]);
            $zoneId = (int) $pdo->lastInsertId();
        } catch (PDOException $e) {
            if ($e->getCode() === "23000") {
                fail("That zone code already exists in this location.", 409);
            }
            throw $e;
        }
        audit((int) $admin["id"], "create", "parking_zone", $zoneId, $name);
        json_response(["ok" => true, "id" => $zoneId], 201);
    }
    if (
        preg_match('#^admin/locations/(\d+)/spaces$#', $route, $match) &&
        $method === "POST"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $locationId = (int) $match[1];
        $data = input();
        $codes = [];
        if (array_key_exists("space_codes", $data)) {
            if (!is_array($data["space_codes"])) {
                fail("Space codes must be sent as a list.", 422);
            }
            foreach ($data["space_codes"] as $rawCode) {
                $code = strtoupper(trim((string) $rawCode));
                if ($code !== "") {
                    $codes[] = $code;
                }
            }
        } else {
            $code = strtoupper(value($data, "space_code", 30));
            if ($code !== "") {
                $codes[] = $code;
            }
        }
        $type = strtolower(value($data, "space_type", 20) ?: "standard");
        $status = strtolower(value($data, "status", 20) ?: "available");
        $normalizedCodes = [];
        foreach ($codes as $code) {
            if (mb_strlen($code) > 20) {
                fail("Each space code must be 20 characters or fewer.", 422);
            }
            $key = strtoupper($code);
            if (isset($normalizedCodes[$key])) {
                fail("Each space code must be unique.", 422);
            }
            $normalizedCodes[$key] = $code;
        }
        $codes = array_values($normalizedCodes);
        if (
            !$codes ||
            count($codes) > 500 ||
            !in_array(
                $type,
                ["standard", "compact", "ev", "accessible"],
                true,
            ) ||
            !in_array(
                $status,
                ["available", "occupied", "reserved", "maintenance", "blocked"],
                true,
            )
        ) {
            fail(
                "Enter 1 to 500 unique space codes, a valid type, and valid status.",
                422,
            );
        }
        $requestedZoneId = (int) ($data["zone_id"] ?? 0);
        $zoneId = $requestedZoneId
            ? first_id(
                "SELECT id FROM parking_zones WHERE id=? AND location_id=?",
                [$requestedZoneId, $locationId],
            )
            : first_id(
                "SELECT id FROM parking_zones WHERE location_id=? ORDER BY id LIMIT 1",
                [$locationId],
            );
        if (!$zoneId) {
            fail("Location not found.", 404);
        }
        try {
            $pdo->beginTransaction();
            $stmt = $pdo->prepare(
                "INSERT INTO parking_spaces(zone_id,space_code,space_type,status,has_ev_charger,sensor_identifier,last_sensor_sync_at) VALUES(?,?,?,?,?,?,NOW())",
            );
            $spaceIds = [];
            foreach ($codes as $code) {
                $stmt->execute([
                    $zoneId,
                    $code,
                    $type,
                    $status,
                    $type === "ev" ? 1 : 0,
                    "MANUAL-" . $locationId . "-" . $code,
                ]);
                $spaceIds[] = (int) $pdo->lastInsertId();
            }
            $count = $pdo->prepare(
                "SELECT COUNT(*) FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=?",
            );
            $count->execute([$locationId]);
            $pdo->prepare(
                "UPDATE parking_locations SET total_capacity=? WHERE id=?",
            )->execute([(int) $count->fetchColumn(), $locationId]);
            $pdo->commit();
        } catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($e->getCode() === "23000") {
                fail("That space code already exists in this location.", 409);
            }
            throw $e;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        foreach ($spaceIds as $index => $spaceId) {
            audit(
                (int) $admin["id"],
                "create",
                "parking_space",
                $spaceId,
                $codes[$index],
            );
        }
        json_response(
            [
                "ok" => true,
                "ids" => $spaceIds,
                "count" => count($spaceIds),
            ],
            201,
        );
    }
    if (
        preg_match('#^admin/locations/(\d+)$#', $route, $match) &&
        $method === "PUT"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $id = (int) $match[1];
        $data = input();
        $name = value($data, "name", 150);
        $address = value($data, "address", 255);
        $area = value($data, "area", 100);
        $rate = (float) ($data["rate"] ?? 0);
        $capacity = (int) ($data["capacity"] ?? 0);
        $status = value($data, "status", 20);
        $hasManagerAssignment = array_key_exists("manager_user_id", $data);
        $managerId = (int) ($data["manager_user_id"] ?? 0);
        if (
            $name === "" ||
            $address === "" ||
            $area === "" ||
            $rate <= 0 ||
            $capacity < 1 ||
            !in_array(
                $status,
                ["draft", "operational", "paused", "closed"],
                true,
            )
        ) {
            fail("Complete all location fields with valid values.", 422);
        }
        $pdo->beginTransaction();
        try {
            $previous = $pdo->prepare(
                "SELECT DISTINCT manager_user_id FROM manager_location_assignments WHERE location_id=?",
            );
            $previous->execute([$id]);
            $previousManagers = array_map(
                "intval",
                $previous->fetchAll(PDO::FETCH_COLUMN),
            );
            $stmt = $pdo->prepare(
                "UPDATE parking_locations SET name=?,address=?,area=?,base_hourly_rate=?,status=? WHERE id=?",
            );
            $stmt->execute([$name, $address, $area, $rate, $status, $id]);
            $exists = $pdo->prepare(
                "SELECT id FROM parking_locations WHERE id=?",
            );
            $exists->execute([$id]);
            if (!$exists->fetch()) {
                fail("Location not found.", 404);
            }
            synchronize_location_capacity($pdo, $id, $capacity);
            if ($hasManagerAssignment) {
                $pdo->prepare(
                    "DELETE FROM manager_location_assignments WHERE location_id=?",
                )->execute([$id]);
                foreach ($previousManagers as $previousManagerId) {
                    ensure_manager_primary_assignment($pdo, $previousManagerId);
                }
                if ($managerId) {
                    $pdo->prepare(
                        "UPDATE manager_location_assignments SET is_primary=0 WHERE manager_user_id=?",
                    )->execute([$managerId]);
                    $pdo->prepare(
                        "INSERT INTO manager_location_assignments(manager_user_id,location_id,is_primary) VALUES(?,?,1)",
                    )->execute([$managerId, $id]);
                    ensure_manager_primary_assignment($pdo, $managerId);
                }
            }
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        audit((int) $admin["id"], "update", "parking_location", $id, $name);
        json_response(["ok" => true]);
    }
    if ($route === "admin/pricing-preview" && $method === "GET") {
        require_login(["admin"]);
        $locationId = (int) ($_GET["location_id"] ?? 0);
        $starts = trim((string) ($_GET["starts_at"] ?? ""));
        $hours = (int) ($_GET["duration_hours"] ?? 0);
        if (
            $locationId < 1 ||
            $hours < 1 ||
            $hours > 24 ||
            strtotime($starts) === false
        ) {
            fail(
                "Choose a location, valid preview time, and duration from 1 to 24 hours.",
                422,
            );
        }
        $location = $pdo->prepare(
            "SELECT id,name,base_hourly_rate FROM parking_locations WHERE id=? AND status='operational' LIMIT 1",
        );
        $location->execute([$locationId]);
        $location = $location->fetch();
        if (!$location) {
            fail("The selected parking location is not operational.", 404);
        }
        $when = (new DateTimeImmutable($starts))->format("Y-m-d H:i:s");
        $time = (new DateTimeImmutable($when))->format("H:i:s");
        $day = (int) (new DateTimeImmutable($when))->format("N");
        $base = (float) $location["base_hourly_rate"];
        $quote = reservation_quote($pdo, $locationId, $when, $hours, $base);
        $rate = $quote["hourly_rate"];
        $rules = $pdo->prepare(
            "SELECT name,adjustment_type,adjustment_value FROM dynamic_pricing_rules WHERE is_active=1 AND (location_id=? OR location_id IS NULL) AND (day_of_week IS NULL OR day_of_week=?) AND ((start_time<=end_time AND ? >= start_time AND ? < end_time) OR (start_time>end_time AND (? >= start_time OR ? < end_time))) ORDER BY id ASC",
        );
        $rules->execute([$locationId, $day, $time, $time, $time, $time]);
        $applied = $rules->fetchAll();
        $baseParking = round($base * $hours, 2);
        $parkingSubtotal = $quote["parking_subtotal"];
        $fee = $quote["service_fee"];
        $total = $quote["total_amount"];
        json_response([
            "ok" => true,
            "location" => [
                "id" => (int) $location["id"],
                "name" => $location["name"],
            ],
            "base_hourly_rate" => $base,
            "hourly_rate" => $rate,
            "duration_hours" => $hours,
            "base_parking" => $baseParking,
            "demand_adjustment" => round($parkingSubtotal - $baseParking, 2),
            "parking_subtotal" => $parkingSubtotal,
            "service_fee" => $fee,
            "total_amount" => $total,
            "applied_rules" => $applied,
        ]);
    }
    if ($route === "admin/pricing-rules" && $method === "POST") {
        $admin = require_login(["admin"]);
        require_csrf();
        $data = input();
        $name = value($data, "name", 120);
        $start = value($data, "start_time", 8);
        $end = value($data, "end_time", 8);
        $locationId = (int) ($data["location_id"] ?? 0);
        $type = value($data, "adjustment_type", 20) ?: "percentage";
        $adjust = (float) ($data["adjustment_value"] ?? 0);
        if (!in_array($type, ["percentage", "fixed_amount"], true)) {
            fail("Choose a valid pricing adjustment type.", 422);
        }
        if ($name === "" || $start === "" || $end === "" || $adjust === 0.0) {
            fail("Pricing rule name, times, and adjustment are required.", 422);
        }
        $stmt = $pdo->prepare(
            "INSERT INTO dynamic_pricing_rules(location_id,name,start_time,end_time,adjustment_type,adjustment_value,is_active,created_by_user_id) VALUES(?,?,?,?,?,?,?,?)",
        );
        $stmt->execute([
            $locationId ?: null,
            $name,
            $start,
            $end,
            $type,
            $adjust,
            !empty($data["is_active"]) ? 1 : 0,
            (int) $admin["id"],
        ]);
        $id = (int) $pdo->lastInsertId();
        audit((int) $admin["id"], "create", "pricing_rule", $id, $name);
        json_response(["ok" => true, "id" => $id], 201);
    }
    if ($route === "admin/pricing-rules" && $method === "GET") {
        require_login(["admin"]);
        $sql =
            "SELECT p.*,l.name AS location_name FROM dynamic_pricing_rules p LEFT JOIN parking_locations l ON l.id=p.location_id ORDER BY p.created_at DESC,p.id DESC";
        json_response(["ok" => true, "rules" => $pdo->query($sql)->fetchAll()]);
    }
    if (
        preg_match('#^admin/pricing-rules/(\d+)$#', $route, $match) &&
        $method === "PUT"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $id = (int) $match[1];
        $data = input();
        $name = value($data, "name", 120);
        $start = value($data, "start_time", 8);
        $end = value($data, "end_time", 8);
        $locationId = (int) ($data["location_id"] ?? 0);
        $type = value($data, "adjustment_type", 20) ?: "percentage";
        $adjust = (float) ($data["adjustment_value"] ?? 0);
        if (!in_array($type, ["percentage", "fixed_amount"], true)) {
            fail("Choose a valid pricing adjustment type.", 422);
        }
        if ($name === "" || $start === "" || $end === "" || $adjust === 0.0) {
            fail("Pricing rule name, times, and adjustment are required.", 422);
        }
        $stmt = $pdo->prepare(
            "UPDATE dynamic_pricing_rules SET location_id=?,name=?,start_time=?,end_time=?,adjustment_type=?,adjustment_value=?,is_active=? WHERE id=?",
        );
        $stmt->execute([
            $locationId ?: null,
            $name,
            $start,
            $end,
            $type,
            $adjust,
            !empty($data["is_active"]) ? 1 : 0,
            $id,
        ]);
        if (!$stmt->rowCount()) {
            $check = $pdo->prepare(
                "SELECT id FROM dynamic_pricing_rules WHERE id=?",
            );
            $check->execute([$id]);
            if (!$check->fetch()) {
                fail("Pricing rule not found.", 404);
            }
        }
        audit((int) $admin["id"], "update", "pricing_rule", $id, $name);
        json_response(["ok" => true]);
    }
    if (
        preg_match('#^admin/pricing-rules/(\d+)$#', $route, $match) &&
        $method === "DELETE"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $id = (int) $match[1];
        $rule = $pdo->prepare(
            "SELECT name FROM dynamic_pricing_rules WHERE id=?",
        );
        $rule->execute([$id]);
        $name = $rule->fetchColumn();
        if ($name === false) {
            fail("Pricing rule not found.", 404);
        }
        $pdo->prepare("DELETE FROM dynamic_pricing_rules WHERE id=?")->execute([
            $id,
        ]);
        audit(
            (int) $admin["id"],
            "delete",
            "pricing_rule",
            $id,
            (string) $name,
        );
        json_response(["ok" => true]);
    }
    if ($route === "admin/violation-categories" && $method === "POST") {
        $admin = require_login(["admin"]);
        require_csrf();
        $data = input();
        $name = value($data, "name", 120);
        $description = value($data, "description", 500);
        $severity = strtolower(value($data, "severity", 20));
        $penalty = (float) ($data["penalty"] ?? 0);
        if (!in_array($severity, ["low", "medium", "high", "critical"], true)) {
            $severity = "medium";
        }
        if ($name === "" || $description === "") {
            fail("Category name and description are required.", 422);
        }
        $stmt = $pdo->prepare(
            "INSERT INTO violation_categories(name,description,default_severity,default_penalty) VALUES(?,?,?,?)",
        );
        $stmt->execute([$name, $description, $severity, $penalty]);
        $id = (int) $pdo->lastInsertId();
        audit((int) $admin["id"], "create", "violation_category", $id, $name);
        json_response(["ok" => true, "id" => $id], 201);
    }
    if ($route === "admin/violation-categories" && $method === "GET") {
        require_login(["admin"]);
        json_response([
            "ok" => true,
            "categories" => $pdo
                ->query(
                    "SELECT * FROM violation_categories WHERE is_active=1 ORDER BY default_severity DESC,name",
                )
                ->fetchAll(),
        ]);
    }
    if (
        preg_match('#^admin/violation-categories/(\d+)$#', $route, $match) &&
        $method === "PUT"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $id = (int) $match[1];
        $data = input();
        $name = value($data, "name", 120);
        $description = value($data, "description", 500);
        $severity = strtolower(value($data, "severity", 20));
        $penalty = (float) ($data["penalty"] ?? 0);
        if (
            !in_array($severity, ["low", "medium", "high", "critical"], true) ||
            $name === "" ||
            $description === ""
        ) {
            fail(
                "Category name, description, and valid severity are required.",
                422,
            );
        }
        $stmt = $pdo->prepare(
            "UPDATE violation_categories SET name=?,description=?,default_severity=?,default_penalty=? WHERE id=?",
        );
        $stmt->execute([$name, $description, $severity, $penalty, $id]);
        if (!$stmt->rowCount()) {
            $check = $pdo->prepare(
                "SELECT id FROM violation_categories WHERE id=?",
            );
            $check->execute([$id]);
            if (!$check->fetch()) {
                fail("Violation category not found.", 404);
            }
        }
        audit((int) $admin["id"], "update", "violation_category", $id, $name);
        json_response(["ok" => true]);
    }
    if (
        preg_match('#^admin/violation-categories/(\d+)$#', $route, $match) &&
        $method === "DELETE"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $id = (int) $match[1];
        $category = $pdo->prepare(
            "SELECT name FROM violation_categories WHERE id=? AND is_active=1",
        );
        $category->execute([$id]);
        $name = $category->fetchColumn();
        if ($name === false) {
            fail("Active violation category not found.", 404);
        }
        $active = (int) $pdo
            ->query(
                "SELECT COUNT(*) FROM violation_categories WHERE is_active=1",
            )
            ->fetchColumn();
        if ($active <= 1) {
            fail("At least one active violation category is required.", 422);
        }
        $pdo->prepare(
            "UPDATE violation_categories SET is_active=0 WHERE id=?",
        )->execute([$id]);
        audit(
            (int) $admin["id"],
            "deactivate",
            "violation_category",
            $id,
            (string) $name,
        );
        json_response(["ok" => true]);
    }

    if ($route === "admin/forwarded-driver-reports" && $method === "GET") {
        require_login(["admin"]);
        $sql =
            "SELECT v.id,v.violation_code,v.status,v.severity,v.description,v.reported_at,v.resolution_note,c.name AS category,COALESCE(u.full_name,reporter.full_name) AS driver_name,veh.registration_number,l.name AS location_name,m.full_name AS manager_name FROM violations v JOIN violation_categories c ON c.id=v.category_id LEFT JOIN issue_reports i ON v.description LIKE CONCAT('Forwarded driver report ',i.ticket_code,':%') LEFT JOIN reservations r ON r.id=v.reservation_id LEFT JOIN parking_spaces ps ON ps.id=v.space_id LEFT JOIN parking_zones z ON z.id=ps.zone_id LEFT JOIN parking_locations l ON l.id=COALESCE(r.location_id,z.location_id,i.location_id) LEFT JOIN vehicles veh ON veh.id=v.vehicle_id LEFT JOIN users u ON u.id=veh.driver_user_id LEFT JOIN users reporter ON reporter.id=i.driver_user_id LEFT JOIN users m ON m.id=v.assigned_manager_user_id WHERE v.source='driver' AND v.description LIKE 'Forwarded driver report%' ORDER BY v.reported_at DESC,v.id DESC";
        json_response([
            "ok" => true,
            "reports" => $pdo->query($sql)->fetchAll(),
        ]);
    }
    if (
        preg_match(
            '#^admin/forwarded-driver-reports/(\d+)/resolve$#',
            $route,
            $match,
        ) &&
        $method === "POST"
    ) {
        $admin = require_login(["admin"]);
        require_csrf();
        $data = input();
        $note = value($data, "note", 1000);
        $stmt = $pdo->prepare(
            "UPDATE violations SET status='resolved',resolved_at=NOW(),resolution_note=? WHERE id=? AND source='driver' AND description LIKE 'Forwarded driver report%'",
        );
        $stmt->execute([
            $note ?: "Resolved by administrator.",
            (int) $match[1],
        ]);
        if (!$stmt->rowCount()) {
            fail("Forwarded driver report not found.", 404);
        }
        audit(
            (int) $admin["id"],
            "resolve",
            "forwarded_driver_report",
            (int) $match[1],
            $note ?: "Resolved by administrator.",
        );
        json_response(["ok" => true]);
    }

.
    /* Manager operations */
     if ($route === "manager/profile" && $method === "GET") {
        $manager = require_login(["manager"]);
        $stmt = $pdo->prepare(
            "SELECT u.full_name,u.email,u.phone,mp.employee_code,mp.shift_name,a.shift_start,a.shift_end,l.name AS location_name FROM users u LEFT JOIN manager_profiles mp ON mp.user_id=u.id LEFT JOIN manager_location_assignments a ON a.manager_user_id=u.id LEFT JOIN parking_locations l ON l.id=a.location_id WHERE u.id=? ORDER BY a.is_primary DESC,a.id ASC LIMIT 1",
        );
        $stmt->execute([(int) $manager["id"]]);
        json_response(["ok" => true, "profile" => $stmt->fetch()]);
    } 
    if ($route === "manager/profile" && $method === "PUT") {
        $manager = require_login(["manager"]);
        require_csrf();
        $data = input();
        $name = value($data, "full_name", 120);
        $phone = value($data, "phone", 30);
        if ($name === "") {
            fail("Your full name is required.", 422);
        }
        $pdo->prepare(
            "UPDATE users SET full_name=?,phone=? WHERE id=?",
        )->execute([$name, $phone ?: null, (int) $manager["id"]]);
        audit(
            (int) $manager["id"],
            "update",
            "manager_profile",
            (int) $manager["id"],
            $name,
        );
        json_response(["ok" => true]);
    }
    if ($route === "manager/dashboard" && $method === "GET") {
        $manager = require_login(["manager"]);
        $locationId = first_id(
            "SELECT location_id FROM manager_location_assignments WHERE manager_user_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [(int) $manager["id"]],
        );
        if (!$locationId) {
            fail("No parking location is assigned to this manager.", 422);
        }
        $stmt = $pdo->prepare(
            "SELECT (SELECT COUNT(*) FROM reservations WHERE location_id=? AND DATE(starts_at)=CURDATE() AND status NOT IN ('cancelled','expired','pending_payment')) reservations_today, (SELECT COUNT(*) FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=? AND ps.status='occupied') occupied, (SELECT COUNT(*) FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=? AND ps.status='available') free_spaces, (SELECT COUNT(*) FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=?) spaces, (SELECT COUNT(*) FROM reservations WHERE location_id=? AND status IN ('confirmed','waiting_check_in','active')) awaiting_verification, (SELECT COUNT(*) FROM violations v JOIN parking_spaces ps ON ps.id=v.space_id JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=? AND v.status IN ('open','under_review')) open_violations, (SELECT COUNT(*) FROM reservations WHERE location_id=? AND status IN ('confirmed','waiting_check_in')) awaiting_check_in, (SELECT COUNT(*) FROM reservations WHERE location_id=? AND status='active') awaiting_check_out",
        );
        $stmt->execute([
            $locationId,
            $locationId,
            $locationId,
            $locationId,
            $locationId,
            $locationId,
            $locationId,
            $locationId,
        ]);
        $data = $stmt->fetch();
        $location = $pdo->prepare(
            "SELECT name,address FROM parking_locations WHERE id=?",
        );
        $location->execute([$locationId]);
        $data["location"] = $location->fetch();
        $data["location_id"] = $locationId;
        $capacity = (int) ($data["spaces"] ?? 0);
        $occupancyCount = $pdo->prepare(
            "SELECT COUNT(*) FROM reservations WHERE location_id=? AND status NOT IN ('cancelled','expired','pending_payment') AND starts_at < ? AND ends_at > ?",
        );
        $todayStart = new DateTimeImmutable("today");
        $todayOccupancy = [];
        for ($hour = 6; $hour <= 20; $hour += 2) {
            $from = $todayStart->setTime($hour, 0);
            $to = $from->modify("+2 hours");
            $occupancyCount->execute([
                $locationId,
                $to->format("Y-m-d H:i:s"),
                $from->format("Y-m-d H:i:s"),
            ]);
            $occupiedAtWindow = (int) $occupancyCount->fetchColumn();
            $todayOccupancy[] = [
                "label" => $from->format("g A"),
                "value" => $capacity
                    ? min(100, (int) round(($occupiedAtWindow * 100) / $capacity))
                    : 0,
            ];
        }
        $weekStart = (new DateTimeImmutable("monday this week"))->setTime(0, 0);
        $weekOccupancy = [];
        for ($day = 0; $day < 7; $day++) {
            $from = $weekStart->modify("+$day days");
            $to = $from->modify("+1 day");
            $occupancyCount->execute([
                $locationId,
                $to->format("Y-m-d H:i:s"),
                $from->format("Y-m-d H:i:s"),
            ]);
            $occupiedOnDay = (int) $occupancyCount->fetchColumn();
            $weekOccupancy[] = [
                "label" => $from->format("D"),
                "value" => $capacity
                    ? min(100, (int) round(($occupiedOnDay * 100) / $capacity))
                    : 0,
            ];
        }
        $stay = $pdo->prepare(
            "SELECT COALESCE(AVG(CASE WHEN actual_check_in_at IS NOT NULL THEN TIMESTAMPDIFF(MINUTE,actual_check_in_at,COALESCE(actual_check_out_at,NOW())) ELSE TIMESTAMPDIFF(MINUTE,starts_at,ends_at) END),0) FROM reservations WHERE location_id=? AND DATE(starts_at)=CURDATE() AND status NOT IN ('cancelled','expired','pending_payment')",
        );
        $stay->execute([$locationId]);
        $currentPercent = $capacity
            ? (int) round(((int) ($data["occupied"] ?? 0) * 100) / $capacity)
            : 0;
        $peakPercent = max(
            $currentPercent,
            ...array_column($todayOccupancy, "value"),
        );
        $activityStmt = $pdo->prepare(
            "SELECT h.status,h.created_at,v.registration_number,ps.space_code FROM reservation_status_history h JOIN reservations r ON r.id=h.reservation_id JOIN vehicles v ON v.id=r.vehicle_id LEFT JOIN parking_spaces ps ON ps.id=r.space_id WHERE r.location_id=? AND h.status IN ('active','completed') ORDER BY h.created_at DESC,h.id DESC LIMIT 8",
        );
        $activityStmt->execute([$locationId]);
        json_response([
            "ok" => true,
            "metrics" => $data,
            "occupancy" => [
                "current_percent" => min(100, $currentPercent),
                "peak_percent" => min(100, $peakPercent),
                "average_stay_minutes" => (int) round((float) $stay->fetchColumn()),
                "today" => $todayOccupancy,
                "week" => $weekOccupancy,
            ],
            "activity" => $activityStmt->fetchAll(),
        ]);
    }
    if ($route === "manager/reservations" && $method === "GET") {
        $manager = require_login(["manager"]);
        $locationId = first_id(
            "SELECT location_id FROM manager_location_assignments WHERE manager_user_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [(int) $manager["id"]],
        );
        $stmt = $pdo->prepare(
            "SELECT r.id,r.reservation_code,r.starts_at,r.ends_at,r.status,r.total_amount,u.full_name,v.registration_number,ps.space_code FROM reservations r JOIN users u ON u.id=r.driver_user_id JOIN vehicles v ON v.id=r.vehicle_id LEFT JOIN parking_spaces ps ON ps.id=r.space_id WHERE r.location_id=? ORDER BY r.starts_at DESC LIMIT 100",
        );
        $stmt->execute([$locationId]);
        json_response(["ok" => true, "reservations" => $stmt->fetchAll()]);
    }
    if (
        preg_match('#^manager/reservations/(\d+)$#', $route, $match) &&
        $method === "GET"
    ) {
        $manager = require_login(["manager"]);
        $stmt = $pdo->prepare(
            "SELECT r.id,r.reservation_code,r.status,r.starts_at,r.ends_at,r.actual_check_in_at,r.actual_check_out_at,r.hourly_rate,r.service_fee,r.discount_amount,r.total_amount,r.notes,r.created_at,r.updated_at,u.full_name AS driver_name,u.email AS driver_email,u.phone AS driver_phone,v.registration_number,v.make_model,v.vehicle_type,v.color,l.name AS location_name,l.address AS location_address,ps.space_code,z.code AS zone_code,p.payment_reference,p.amount AS payment_amount,p.method AS payment_method,p.status AS payment_status,p.paid_at FROM reservations r JOIN users u ON u.id=r.driver_user_id JOIN vehicles v ON v.id=r.vehicle_id JOIN parking_locations l ON l.id=r.location_id LEFT JOIN parking_spaces ps ON ps.id=r.space_id LEFT JOIN parking_zones z ON z.id=ps.zone_id LEFT JOIN payments p ON p.id=(SELECT id FROM payments WHERE reservation_id=r.id ORDER BY id DESC LIMIT 1) JOIN manager_location_assignments a ON a.location_id=r.location_id WHERE r.id=? AND a.manager_user_id=? LIMIT 1",
        );
        $stmt->execute([(int) $match[1], (int) $manager["id"]]);
        $reservation = $stmt->fetch();
        if (!$reservation) {
            fail("Reservation not found in your assigned location.", 404);
        }
        json_response(["ok" => true, "reservation" => $reservation]);
    }
    if ($route === "manager/spaces" && $method === "GET") {
        $manager = require_login(["manager"]);
        $locationId = first_id(
            "SELECT location_id FROM manager_location_assignments WHERE manager_user_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [(int) $manager["id"]],
        );
        $stmt = $pdo->prepare(
            "SELECT ps.id,ps.space_code,ps.space_type,ps.status,ps.has_ev_charger,z.name AS zone_name,z.code AS zone_code FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=? ORDER BY z.code,ps.space_code",
        );
        $stmt->execute([$locationId]);
        json_response(["ok" => true, "spaces" => $stmt->fetchAll()]);
    }
    if ($route === "manager/verification" && $method === "GET") {
        $manager = require_login(["manager"]);
        $locationId = first_id(
            "SELECT location_id FROM manager_location_assignments WHERE manager_user_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [(int) $manager["id"]],
        );
        $stmt = $pdo->prepare(
            "SELECT r.id,r.reservation_code,r.status,r.starts_at,r.ends_at,u.id AS driver_user_id,u.full_name,v.registration_number,ps.space_code,CASE WHEN r.status='active' THEN 'check_out' ELSE 'check_in' END AS purpose FROM reservations r JOIN users u ON u.id=r.driver_user_id JOIN vehicles v ON v.id=r.vehicle_id LEFT JOIN parking_spaces ps ON ps.id=r.space_id WHERE r.location_id=? AND r.status IN ('confirmed','waiting_check_in','active') ORDER BY r.starts_at",
        );
        $stmt->execute([$locationId]);
        json_response(["ok" => true, "queue" => $stmt->fetchAll()]);
    }
    if ($route === "manager/report" && $method === "GET") {
        $manager = require_login(["manager"]);
        $locationId = first_id(
            "SELECT location_id FROM manager_location_assignments WHERE manager_user_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [(int) $manager["id"]],
        );
        $location = $pdo->prepare(
            "SELECT name FROM parking_locations WHERE id=?",
        );
        $location->execute([$locationId]);
        $summary = $pdo->prepare(
            "SELECT COUNT(*) AS reservations,COALESCE(SUM(total_amount),0) AS revenue,SUM(status='completed') AS check_outs,SUM(status IN ('active','completed','overstayed')) AS check_ins FROM reservations WHERE location_id=?",
        );
        $summary->execute([$locationId]);
        $violations = $pdo->prepare(
            "SELECT COUNT(*) AS total,SUM(v.status IN ('open','under_review')) AS open_total FROM violations v LEFT JOIN parking_spaces ps ON ps.id=v.space_id LEFT JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=?",
        );
        $violations->execute([$locationId]);
        $spaces = $pdo->prepare(
            "SELECT z.code,COUNT(*) AS total,SUM(ps.status='occupied') AS occupied,SUM(ps.status='available') AS available FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=? GROUP BY z.id ORDER BY z.code",
        );
        $spaces->execute([$locationId]);
        json_response([
            "ok" => true,
            "location" => $location->fetch(),
            "summary" => $summary->fetch(),
            "violations" => $violations->fetch(),
            "zones" => $spaces->fetchAll(),
        ]);
    }
    if ($route === "manager/conversations" && $method === "GET") {
        $manager = require_login(["manager"]);
        $locationId = first_id(
            "SELECT location_id FROM manager_location_assignments WHERE manager_user_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [(int) $manager["id"]],
        );
        $stmt = $pdo->prepare(
            "SELECT u.id,u.full_name,MAX(m.created_at) AS last_at,SUBSTRING_INDEX(GROUP_CONCAT(m.body ORDER BY m.created_at DESC SEPARATOR '|||'),'|||',1) AS last_body,SUM(m.recipient_user_id=? AND m.read_at IS NULL) AS unread FROM messages m JOIN users u ON u.id=CASE WHEN m.sender_user_id=? THEN m.recipient_user_id ELSE m.sender_user_id END LEFT JOIN reservations r ON r.id=m.reservation_id WHERE (m.sender_user_id=? OR m.recipient_user_id=?) AND (r.location_id=? OR r.id IS NULL) GROUP BY u.id ORDER BY last_at DESC",
        );
        $stmt->execute([
            (int) $manager["id"],
            (int) $manager["id"],
            (int) $manager["id"],
            (int) $manager["id"],
            $locationId,
        ]);
        json_response(["ok" => true, "conversations" => $stmt->fetchAll()]);
    }
    if (
        preg_match('#^manager/spaces/(\d+)$#', $route, $match) &&
        $method === "PATCH"
    ) {
        $manager = require_login(["manager"]);
        require_csrf();
        $data = input();
        $status = strtolower(value($data, "status", 20));
        if ($status === "free") {
            $status = "available";
        }
        if (
            !in_array(
                $status,
                ["available", "occupied", "reserved", "maintenance", "blocked"],
                true,
            )
        ) {
            fail("Invalid space status.", 422);
        }
        $spaceId = (int) $match[1];
        $note = value($data, "note", 255);
        $stmt = $pdo->prepare(
            "SELECT ps.id FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id JOIN manager_location_assignments a ON a.location_id=z.location_id WHERE ps.id=? AND a.manager_user_id=?",
        );
        $stmt->execute([$spaceId, (int) $manager["id"]]);
        if (!$stmt->fetch()) {
            fail("Space not found in your assigned location.", 404);
        }
        $pdo->beginTransaction();
        try {
            $pdo->prepare(
                "UPDATE parking_spaces SET status=? WHERE id=?",
            )->execute([$status, $spaceId]);
            $pdo->prepare(
                "INSERT INTO parking_space_status_history(space_id,status,changed_by_user_id,note) VALUES(?,?,?,?)",
            )->execute([
                $spaceId,
                $status,
                (int) $manager["id"],
                $note ?: null,
            ]);
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        audit(
            (int) $manager["id"],
            "update_status",
            "parking_space",
            $spaceId,
            $status,
        );
        json_response(["ok" => true, "status" => $status]);
    }
    if (
        ($route === "manager/check-in" || $route === "manager/check-out") &&
        $method === "POST"
    ) {
        $manager = require_login(["manager"]);
        require_csrf();
        $data = input();
        $code = strtoupper(value($data, "reservation_code", 30));
        $otp = value($data, "otp", 10);
        $purpose = $route === "manager/check-in" ? "check_in" : "check_out";
        if (!preg_match('/^\d{4,8}$/', $otp)) {
            fail("Enter the complete numeric OTP.", 422);
        }
        $stmt = $pdo->prepare(
            "SELECT r.id,r.space_id,r.status FROM reservations r JOIN parking_locations l ON l.id=r.location_id JOIN manager_location_assignments a ON a.location_id=l.id WHERE r.reservation_code=? AND a.manager_user_id=? LIMIT 1",
        );
        $stmt->execute([$code, (int) $manager["id"]]);
        $reservation = $stmt->fetch();
        if (!$reservation) {
            fail("Reservation not found in your assigned location.", 404);
        }
        $allowedStatuses =
            $purpose === "check_in"
                ? ["confirmed", "waiting_check_in"]
                : ["active"];
        if (!in_array($reservation["status"], $allowedStatuses, true)) {
            fail(
                $purpose === "check_in"
                    ? "This reservation is not ready for check-in."
                    : "This reservation is not currently active for check-out.",
                422,
            );
        }
        $otpStmt = $pdo->prepare(
            "SELECT id,otp_hash FROM access_otps WHERE reservation_id=? AND purpose=? AND used_at IS NULL AND expires_at>=NOW() ORDER BY id DESC LIMIT 1",
        );
        $otpStmt->execute([$reservation["id"], $purpose]);
        $row = $otpStmt->fetch();
        if (!$row || !hash_equals($row["otp_hash"], hash("sha256", $otp))) {
            fail("OTP is incorrect or expired.", 422);
        }
        $newStatus = $purpose === "check_in" ? "active" : "completed";
        $spaceStatus = $purpose === "check_in" ? "occupied" : "available";
        $pdo->beginTransaction();
        try {
            $pdo->prepare(
                "UPDATE access_otps SET used_at=NOW(),verified_by_user_id=? WHERE id=?",
            )->execute([(int) $manager["id"], $row["id"]]);
            $pdo->prepare(
                "UPDATE reservations SET status=?, " .
                    ($purpose === "check_in"
                        ? "actual_check_in_at=NOW()"
                        : "actual_check_out_at=NOW()") .
                    " WHERE id=?",
            )->execute([$newStatus, $reservation["id"]]);
            $pdo->prepare(
                "UPDATE parking_spaces SET status=? WHERE id=?",
            )->execute([$spaceStatus, $reservation["space_id"]]);
            $pdo->prepare(
                "INSERT INTO reservation_status_history(reservation_id,status,changed_by_user_id,note) VALUES(?,?,?,?)",
            )->execute([
                $reservation["id"],
                $newStatus,
                (int) $manager["id"],
                "OTP verified by manager.",
            ]);
            $pdo->prepare(
                "INSERT INTO parking_space_status_history(space_id,status,changed_by_user_id,note) VALUES(?,?,?,?)",
            )->execute([
                $reservation["space_id"],
                $spaceStatus,
                (int) $manager["id"],
                "OTP " . $purpose . " completed.",
            ]);
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        audit(
            (int) $manager["id"],
            $purpose,
            "reservation",
            (int) $reservation["id"],
            "OTP verified.",
        );
        json_response(["ok" => true, "status" => $newStatus]);
    }
    if ($route === "manager/issues" && $method === "GET") {
        $manager = require_login(["manager"]);
        $locationId = first_id(
            "SELECT location_id FROM manager_location_assignments WHERE manager_user_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [(int) $manager["id"]],
        );
        $sql =
            "SELECT i.*,u.full_name AS driver_name,u.email AS driver_email,r.reservation_code,v.registration_number,ps.space_code FROM issue_reports i JOIN users u ON u.id=i.driver_user_id LEFT JOIN reservations r ON r.id=i.reservation_id LEFT JOIN vehicles v ON v.id=r.vehicle_id LEFT JOIN parking_spaces ps ON ps.id=r.space_id WHERE i.location_id=? ORDER BY FIELD(i.status,'open','in_progress','resolved','closed'),i.reported_at DESC,i.id DESC";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$locationId]);
        json_response(["ok" => true, "issues" => $stmt->fetchAll()]);
    }
    if (
        preg_match('#^manager/issues/(\d+)/review$#', $route, $match) &&
        $method === "POST"
    ) {
        $manager = require_login(["manager"]);
        require_csrf();
        $data = input();
        $action = value($data, "action", 20);
        $note = value($data, "note", 1000);
        if (!in_array($action, ["review", "resolve", "forward"], true)) {
            fail("Choose a valid review action.", 422);
        }
        $locationId = first_id(
            "SELECT location_id FROM manager_location_assignments WHERE manager_user_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [(int) $manager["id"]],
        );
        $stmt = $pdo->prepare(
            "SELECT * FROM issue_reports WHERE id=? AND location_id=?",
        );
        $stmt->execute([(int) $match[1], $locationId]);
        $issue = $stmt->fetch();
        if (!$issue) {
            fail("Driver report not found in your assigned location.", 404);
        }
        $pdo->beginTransaction();
        try {
            $status = $action === "resolve" ? "resolved" : "in_progress";
            $pdo->prepare(
                "UPDATE issue_reports SET status=?,assigned_to_user_id=?,resolved_at=? WHERE id=?",
            )->execute([
                $status,
                (int) $manager["id"],
                $action === "resolve" ? date("Y-m-d H:i:s") : null,
                (int) $issue["id"],
            ]);
            $result = ["ok" => true, "status" => $status];
            if ($action === "forward") {
                $categoryId = first_id(
                    "SELECT id FROM violation_categories WHERE is_active=1 ORDER BY id LIMIT 1",
                );
                $reservation = $issue["reservation_id"]
                    ? $pdo->prepare(
                        "SELECT vehicle_id,space_id FROM reservations WHERE id=?",
                    )
                    : null;
                if ($reservation) {
                    $reservation->execute([(int) $issue["reservation_id"]]);
                    $reservation = $reservation->fetch() ?: [];
                } else {
                    $reservation = [];
                }
                $code = "VL-" . random_int(10000, 99999);
                $description =
                    "Forwarded driver report " .
                    $issue["ticket_code"] .
                    ": " .
                    $issue["description"] .
                    ($note !== "" ? " | Manager review: " . $note : "");
                $penalty =
                    (float) ($pdo
                        ->query(
                            "SELECT default_penalty FROM violation_categories WHERE id=" .
                                (int) $categoryId,
                        )
                        ->fetchColumn() ?:
                    0);
                $pdo->prepare(
                    "INSERT INTO violations(violation_code,category_id,reservation_id,vehicle_id,space_id,reported_by_user_id,assigned_manager_user_id,source,severity,description,penalty_amount,status) SELECT ?,id,?,?,?,?,?,'driver',default_severity,?,?, 'under_review' FROM violation_categories WHERE id=?",
                )->execute([
                    $code,
                    $issue["reservation_id"] ?: null,
                    $reservation["vehicle_id"] ?? null,
                    $reservation["space_id"] ?? null,
                    (int) $issue["driver_user_id"],
                    (int) $manager["id"],
                    $description,
                    $penalty,
                    (int) $categoryId,
                ]);
                $result["violation_code"] = $code;
            }
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        audit(
            (int) $manager["id"],
            $action,
            "driver_issue",
            (int) $issue["id"],
            $note ?: $issue["ticket_code"],
        );
        json_response($result);
    }
    if ($route === "manager/violations" && $method === "GET") {
        $manager = require_login(["manager"]);
        $locationId = first_id(
            "SELECT location_id FROM manager_location_assignments WHERE manager_user_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [(int) $manager["id"]],
        );
        $stmt = $pdo->prepare(
            "SELECT v.id,v.violation_code,v.severity,v.description,v.penalty_amount,v.status,v.reported_at,c.name AS category,ps.space_code,veh.registration_number,u.full_name FROM violations v JOIN violation_categories c ON c.id=v.category_id LEFT JOIN parking_spaces ps ON ps.id=v.space_id LEFT JOIN vehicles veh ON veh.id=v.vehicle_id LEFT JOIN users u ON u.id=veh.driver_user_id LEFT JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=? ORDER BY v.reported_at DESC",
        );
        $stmt->execute([$locationId]);
        json_response(["ok" => true, "violations" => $stmt->fetchAll()]);
    }
    if (
        preg_match('#^manager/violations/(\d+)/resolve$#', $route, $match) &&
        $method === "POST"
    ) {
        $manager = require_login(["manager"]);
        require_csrf();
        $data = input();
        $status =
            value($data, "status", 20) === "dismissed"
                ? "dismissed"
                : "resolved";
        $note = value($data, "note", 1000);
        $stmt = $pdo->prepare(
            "UPDATE violations SET status=?,resolved_at=NOW(),resolution_note=?,assigned_manager_user_id=? WHERE id=?",
        );
        $stmt->execute([
            $status,
            $note ?: null,
            (int) $manager["id"],
            (int) $match[1],
        ]);
        if (!$stmt->rowCount()) {
            fail("Violation not found.", 404);
        }
        audit(
            (int) $manager["id"],
            $status,
            "violation",
            (int) $match[1],
            $note,
        );
        json_response(["ok" => true]);
    }

    /* Driver account and reservations */
    /*
     * ================================================================
     * DRIVER FEATURE 01 — PROFILE AND ACCOUNT SETTINGS
     * GET  driver/profile : reads the signed-in driver's account data.
     * PUT  driver/profile : validates and updates users + driver_profiles.
     * ================================================================
     */
    if ($route === "driver/profile" && $method === "GET") {
        $driver = require_login(["driver"]);
        $stmt = $pdo->prepare(
            "SELECT u.full_name,u.email,u.phone,d.city,d.emergency_contact,d.preferred_language,d.receive_updates FROM users u JOIN driver_profiles d ON d.user_id=u.id WHERE u.id=?",
        );
        $stmt->execute([(int) $driver["id"]]);
        json_response(["ok" => true, "profile" => $stmt->fetch()]);
    }
    if ($route === "driver/profile" && $method === "PUT") {
        $driver = require_login(["driver"]);
        require_csrf();
        $data = input();
        $name = value($data, "name", 120);
        $email = strtolower(value($data, "email", 190));
        $phone = value($data, "phone", 30);
        $city = value($data, "city", 100);
        $contact = value($data, "emergency_contact", 120);
        $language = value($data, "language", 20);
        if (
            $name === "" ||
            !filter_var($email, FILTER_VALIDATE_EMAIL) ||
            $phone === ""
        ) {
            fail("Name, email, and phone are required.", 422);
        }
        $pdo->beginTransaction();
        try {
            $pdo->prepare(
                "UPDATE users SET full_name=?,email=?,phone=? WHERE id=?",
            )->execute([$name, $email, $phone, (int) $driver["id"]]);
            $pdo->prepare(
                "UPDATE driver_profiles SET city=?,emergency_contact=?,preferred_language=?,receive_updates=? WHERE user_id=?",
            )->execute([
                $city ?: "Dhaka",
                $contact ?: null,
                $language ?: "English",
                !empty($data["receive_updates"]) ? 1 : 0,
                (int) $driver["id"],
            ]);
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($e instanceof PDOException && $e->getCode() === "23000") {
                fail("That email address is already in use.", 409);
            }
            throw $e;
        }
        audit(
            (int) $driver["id"],
            "update",
            "driver_profile",
            (int) $driver["id"],
            "Profile updated.",
        );
        json_response(["ok" => true]);
    }
    /*
     * ================================================================
     * DRIVER FEATURE 02 — VEHICLE MANAGEMENT
     * GET  driver/vehicles      : lists the driver's vehicles.
     * POST driver/vehicles      : creates a vehicle and handles primary flag.
     * PUT  driver/vehicles/{id} : edits an owned vehicle safely.
     * ================================================================
     */
    if ($route === "driver/vehicles" && $method === "GET") {
        $driver = require_login(["driver"]);
        $stmt = $pdo->prepare(
            "SELECT id,registration_number,make_model,vehicle_year,vehicle_type,color,powertrain,is_primary FROM vehicles WHERE driver_user_id=? ORDER BY is_primary DESC,id DESC",
        );
        $stmt->execute([(int) $driver["id"]]);
        json_response(["ok" => true, "vehicles" => $stmt->fetchAll()]);
    }
    if ($route === "driver/vehicles" && $method === "POST") {
        $driver = require_login(["driver"]);
        require_csrf();
        $data = input();
        $plate = strtoupper(value($data, "registration_number", 40));
        $make = value($data, "make_model", 100);
        $year = (int) ($data["vehicle_year"] ?? 0);
        if (
            $plate === "" ||
            $make === "" ||
            $year < 1990 ||
            $year > (int) date("Y") + 1
        ) {
            fail("Enter valid vehicle details.", 422);
        }
        $isPrimary = !empty($data["is_primary"]);
        $pdo->beginTransaction();
        try {
            if ($isPrimary) {
                $pdo->prepare(
                    "UPDATE vehicles SET is_primary=0 WHERE driver_user_id=?",
                )->execute([(int) $driver["id"]]);
            }
            $stmt = $pdo->prepare(
                "INSERT INTO vehicles(driver_user_id,registration_number,make_model,vehicle_year,vehicle_type,color,powertrain,is_primary) VALUES(?,?,?,?,?,?,?,?)",
            );
            $stmt->execute([
                (int) $driver["id"],
                $plate,
                $make,
                $year,
                normalized_vehicle_type(
                    (string) ($data["vehicle_type"] ?? "sedan"),
                ),
                value($data, "color", 50) ?: null,
                strtolower(value($data, "powertrain", 20) ?: "petrol"),
                $isPrimary ? 1 : 0,
            ]);
            $id = (int) $pdo->lastInsertId();
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($e instanceof PDOException && $e->getCode() === "23000") {
                fail("That registration number already exists.", 409);
            }
            throw $e;
        }
        audit((int) $driver["id"], "create", "vehicle", $id, $plate);
        json_response(["ok" => true, "id" => $id], 201);
    }
    if (
        preg_match('#^driver/vehicles/(\d+)$#', $route, $match) &&
        $method === "PUT"
    ) {
        $driver = require_login(["driver"]);
        require_csrf();
        $data = input();
        $id = (int) $match[1];
        $plate = strtoupper(value($data, "registration_number", 40));
        $make = value($data, "make_model", 100);
        $year = (int) ($data["vehicle_year"] ?? 0);
        if (
            $plate === "" ||
            $make === "" ||
            $year < 1990 ||
            $year > (int) date("Y") + 1
        ) {
            fail("Enter valid vehicle details.", 422);
        }
        $isPrimary = !empty($data["is_primary"]);
        $pdo->beginTransaction();
        try {
            $check = $pdo->prepare(
                "SELECT id FROM vehicles WHERE id=? AND driver_user_id=? FOR UPDATE",
            );
            $check->execute([$id, (int) $driver["id"]]);
            if (!$check->fetch()) {
                fail("Vehicle not found.", 404);
            }
            if ($isPrimary) {
                $pdo->prepare(
                    "UPDATE vehicles SET is_primary=0 WHERE driver_user_id=?",
                )->execute([(int) $driver["id"]]);
            }
            $stmt = $pdo->prepare(
                "UPDATE vehicles SET registration_number=?,make_model=?,vehicle_year=?,vehicle_type=?,color=?,powertrain=?,is_primary=? WHERE id=? AND driver_user_id=?",
            );
            $stmt->execute([
                $plate,
                $make,
                $year,
                normalized_vehicle_type(
                    (string) ($data["vehicle_type"] ?? "sedan"),
                ),
                value($data, "color", 50) ?: null,
                strtolower(value($data, "powertrain", 20) ?: "petrol"),
                $isPrimary ? 1 : 0,
                $id,
                (int) $driver["id"],
            ]);
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($e instanceof PDOException && $e->getCode() === "23000") {
                fail("That registration number already exists.", 409);
            }
            throw $e;
        }
        audit((int) $driver["id"], "update", "vehicle", $id, $plate);
        json_response(["ok" => true]);
    }
    /*
     * ================================================================
     * DRIVER FEATURE 03 — LOCATION, ZONE, AND SPACE DISCOVERY
     * GET driver/locations : lists operational locations and free-space counts.
     * GET driver/zones     : lists zones belonging to the selected location.
     * GET driver/spaces    : lists only available spaces, optionally by zone.
     * ================================================================
     */
    if ($route === "driver/locations" && $method === "GET") {
        require_login(["driver"]);
        $stmt = $pdo->query(
            "SELECT l.id,l.name,l.address,l.area,l.base_hourly_rate, SUM(ps.status='available') available_spaces FROM parking_locations l LEFT JOIN parking_zones z ON z.location_id=l.id LEFT JOIN parking_spaces ps ON ps.zone_id=z.id WHERE l.status='operational' GROUP BY l.id ORDER BY l.name",
        );
        json_response(["ok" => true, "locations" => $stmt->fetchAll()]);
    }
    if ($route === "driver/zones" && $method === "GET") {
        require_login(["driver"]);
        $locationId = (int) ($_GET["location_id"] ?? 0);
        if ($locationId < 1) {
            fail("A parking location is required.", 422);
        }
        $stmt = $pdo->prepare(
            "SELECT z.id,z.code,z.name,z.floor_label,COUNT(ps.id) AS spaces_total,SUM(ps.status='available') AS available_spaces FROM parking_zones z LEFT JOIN parking_spaces ps ON ps.zone_id=z.id WHERE z.location_id=? GROUP BY z.id ORDER BY z.code,z.id",
        );
        $stmt->execute([$locationId]);
        json_response(["ok" => true, "zones" => $stmt->fetchAll()]);
    }
    if ($route === "driver/spaces" && $method === "GET") {
        require_login(["driver"]);
        $locationId = (int) ($_GET["location_id"] ?? 0);
        if ($locationId < 1) {
            fail("A parking location is required.", 422);
        }
        $zoneId = (int) ($_GET["zone_id"] ?? 0);
        $sql =
            "SELECT ps.id,ps.space_code,ps.space_type,ps.status,z.id AS zone_id,z.code AS zone_code,z.name AS zone_name,z.floor_label FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id WHERE z.location_id=? AND ps.status='available'";
        $params = [$locationId];
        if ($zoneId > 0) {
            $sql .= " AND z.id=?";
            $params[] = $zoneId;
        }
        $sql .= " ORDER BY z.code,ps.space_code";
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        json_response(["ok" => true, "spaces" => $stmt->fetchAll()]);
    }
    /*
     * ================================================================
     * DRIVER FEATURE 04 — DYNAMIC PRICE QUOTE
     * GET driver/quote : calculates base rate, dynamic rate, parking subtotal,
     * service fee, discount, and final total before the driver books.
     * The same reservation_quote() calculation is used during booking.
     * ================================================================
     */
    if ($route === "driver/quote" && $method === "GET") {
        require_login(["driver"]);
        $locationId = (int) ($_GET["location_id"] ?? 0);
        $starts = trim((string) ($_GET["starts_at"] ?? ""));
        $hours = (int) ($_GET["duration_hours"] ?? 0);
        if (
            $locationId < 1 ||
            $hours < 1 ||
            $hours > 24 ||
            strtotime($starts) === false
        ) {
            fail("Choose a location, valid time, and duration.", 422);
        }
        $stmt = $pdo->prepare(
            'SELECT base_hourly_rate FROM parking_locations WHERE id=? AND status=\'operational\'',
        );
        $stmt->execute([$locationId]);
        $base = $stmt->fetchColumn();
        if ($base === false) {
            fail("Parking location not found.", 404);
        }
        $quote = reservation_quote(
            $pdo,
            $locationId,
            (new DateTimeImmutable($starts))->format("Y-m-d H:i:s"),
            $hours,
            (float) $base,
        );
        json_response(array_merge(["ok" => true], $quote));
    }
    /*
     * ================================================================
     * DRIVER FEATURE 05 — RESERVATION AND PAYMENT FLOW
     * GET  driver/reservations : returns the driver's booking history.
     * POST driver/reservations : validates ownership/availability, creates the
     * reservation, records payment, reserves the space, and creates both OTPs.
     * ================================================================
     */
    if ($route === "driver/reservations" && $method === "GET") {
        $driver = require_login(["driver"]);
        $stmt = $pdo->prepare(
            "SELECT r.*,l.name location_name,ps.space_code,v.registration_number,v.make_model FROM reservations r JOIN parking_locations l ON l.id=r.location_id LEFT JOIN parking_spaces ps ON ps.id=r.space_id JOIN vehicles v ON v.id=r.vehicle_id WHERE r.driver_user_id=? ORDER BY r.updated_at DESC,r.starts_at DESC,r.id DESC",
        );
        $stmt->execute([(int) $driver["id"]]);
        json_response(["ok" => true, "reservations" => $stmt->fetchAll()]);
    }
    if ($route === "driver/reservations" && $method === "POST") {
        $requestedStart = trim((string) (input()["starts_at"] ?? ""));
        if (
            $requestedStart !== "" &&
            strtotime($requestedStart) !== false &&
            new DateTimeImmutable($requestedStart) <
                (new DateTimeImmutable("now"))->modify("-1 minute")
        ) {
            fail("Choose a future arrival time.", 422);
        }
        $driver = require_login(["driver"]);
        require_csrf();
        $data = input();
        $locationId = (int) ($data["location_id"] ?? 0);
        $spaceId = (int) ($data["space_id"] ?? 0);
        $vehicleId = (int) ($data["vehicle_id"] ?? 0);
        $starts = value($data, "starts_at", 30);
        $hours = (int) ($data["duration_hours"] ?? 0);
        if (
            $locationId < 1 ||
            $spaceId < 1 ||
            $vehicleId < 1 ||
            $hours < 1 ||
            $hours > 24 ||
            strtotime($starts) === false
        ) {
            fail(
                "Choose a valid location, available space, vehicle, time, and duration.",
                422,
            );
        }
        $startDate = (new DateTimeImmutable($starts))->format("Y-m-d H:i:s");
        $endDate = (new DateTimeImmutable($startDate))
            ->modify("+$hours hours")
            ->format("Y-m-d H:i:s");
        $pdo->beginTransaction();
        try {
            $vehicle = first_id(
                "SELECT id FROM vehicles WHERE id=? AND driver_user_id=?",
                [$vehicleId, (int) $driver["id"]],
            );
            $space = $pdo->prepare(
                "SELECT ps.id,l.base_hourly_rate FROM parking_spaces ps JOIN parking_zones z ON z.id=ps.zone_id JOIN parking_locations l ON l.id=z.location_id WHERE ps.id=? AND z.location_id=? AND ps.status='available' FOR UPDATE",
            );
            $space->execute([$spaceId, $locationId]);
            $spaceRow = $space->fetch();
            $overlap = first_id(
                "SELECT id FROM reservations WHERE space_id=? AND status IN ('confirmed','waiting_check_in','active') AND starts_at < ? AND ends_at > ? LIMIT 1",
                [$spaceId, $endDate, $startDate],
            );
            if (!$vehicle) {
                fail("Selected vehicle was not found.", 404);
            }
            if (!$spaceRow || $overlap) {
                fail(
                    "That parking space is no longer available. Please select another.",
                    409,
                );
            }
            $quote = reservation_quote(
                $pdo,
                $locationId,
                $startDate,
                $hours,
                (float) $spaceRow["base_hourly_rate"],
            );
            $rate = $quote["hourly_rate"];
            $fee = $quote["service_fee"];
            $total = $quote["total_amount"];
            $code = "PF-" . random_int(10000, 99999);
            $stmt = $pdo->prepare(
                "INSERT INTO reservations(reservation_code,driver_user_id,vehicle_id,location_id,space_id,starts_at,ends_at,hourly_rate,service_fee,total_amount,status) VALUES(?,?,?,?,?,?,?,?,?,?, 'confirmed')",
            );
            $stmt->execute([
                $code,
                (int) $driver["id"],
                $vehicleId,
                $locationId,
                $spaceId,
                $startDate,
                $endDate,
                $rate,
                $fee,
                $total,
            ]);
            $reservationId = (int) $pdo->lastInsertId();
            $pdo->prepare(
                "UPDATE parking_spaces SET status='reserved' WHERE id=?",
            )->execute([$spaceId]);
            $pdo->prepare(
                'INSERT INTO payments(reservation_id,payment_reference,amount,method,status,paid_at) VALUES(?,?,?,\'card\',\'paid\',NOW())',
            )->execute([$reservationId, "PAY-" . $code, $total]);
            $otp = (string) random_int(1000, 9999);
            $checkoutOtp = (string) random_int(1000, 9999);
            $otpInsert = $pdo->prepare(
                "INSERT INTO access_otps(reservation_id,purpose,otp_hash,expires_at) VALUES(?,?,?,?)",
            );
            $otpInsert->execute([
                $reservationId,
                "check_in",
                hash("sha256", $otp),
                (new DateTimeImmutable($startDate))
                    ->modify("+3 hours")
                    ->format("Y-m-d H:i:s"),
            ]);
            $otpInsert->execute([
                $reservationId,
                "check_out",
                hash("sha256", $checkoutOtp),
                (new DateTimeImmutable($endDate))
                    ->modify("+3 hours")
                    ->format("Y-m-d H:i:s"),
            ]);
            $pdo->prepare(
                "INSERT INTO reservation_status_history(reservation_id,status,changed_by_user_id,note) VALUES(?, 'confirmed', ?, 'Payment recorded and space reserved.')",
            )->execute([$reservationId, (int) $driver["id"]]);
            $pdo->prepare(
                "INSERT INTO parking_space_status_history(space_id,status,changed_by_user_id,note) VALUES(?, 'reserved', ?, ?)",
            )->execute([
                $spaceId,
                (int) $driver["id"],
                "Reservation " . $code . " created.",
            ]);
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        audit(
            (int) $driver["id"],
            "create",
            "reservation",
            $reservationId,
            $code,
        );
        json_response(
            array_merge(
                [
                    "ok" => true,
                    "reservation_code" => $code,
                    "reservation_id" => $reservationId,
                    "check_in_otp" => $otp,
                    "check_out_otp" => $checkoutOtp,
                ],
                $quote,
            ),
            201,
        );
    }
    /*
     * ================================================================
     * DRIVER FEATURE 06 — CANCELLATION AND ACCESS OTP
     * POST driver/reservations/{id}/cancel : cancels an upcoming owned booking
     * and releases its space back to available status.
     * POST .../check-in-otp / .../check-out-otp : issues a fresh OTP only to
     * the reservation owner for the correct access phase.
     * ================================================================
     */
    if (
        preg_match('#^driver/reservations/(\d+)/cancel$#', $route, $match) &&
        $method === "POST"
    ) {
        $driver = require_login(["driver"]);
        require_csrf();
        $reservationId = (int) $match[1];
        $stmt = $pdo->prepare(
            "SELECT id,space_id,status FROM reservations WHERE id=? AND driver_user_id=? FOR UPDATE",
        );
        $pdo->beginTransaction();
        try {
            $stmt->execute([$reservationId, (int) $driver["id"]]);
            $reservation = $stmt->fetch();
            if (!$reservation) {
                fail("Reservation not found for your account.", 404);
            }
            if (
                !in_array(
                    $reservation["status"],
                    ["confirmed", "waiting_check_in"],
                    true,
                )
            ) {
                fail(
                    "Only an upcoming reservation can be cancelled. Ask the manager to check out an active booking.",
                    422,
                );
            }
            $pdo->prepare(
                "UPDATE reservations SET status='cancelled' WHERE id=?",
            )->execute([$reservationId]);
            if ($reservation["space_id"]) {
                $pdo->prepare(
                    "UPDATE parking_spaces SET status='available' WHERE id=? AND status='reserved'",
                )->execute([(int) $reservation["space_id"]]);
                $pdo->prepare(
                    "INSERT INTO parking_space_status_history(space_id,status,changed_by_user_id,note) VALUES(?, 'available', ?, 'Driver cancelled the reservation.')",
                )->execute([
                    (int) $reservation["space_id"],
                    (int) $driver["id"],
                ]);
            }
            $pdo->prepare(
                "INSERT INTO reservation_status_history(reservation_id,status,changed_by_user_id,note) VALUES(?, 'cancelled', ?, 'Driver cancelled the reservation.')",
            )->execute([$reservationId, (int) $driver["id"]]);
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        audit(
            (int) $driver["id"],
            "cancel",
            "reservation",
            $reservationId,
            "Driver cancelled the reservation.",
        );
        json_response(["ok" => true, "status" => "cancelled"]);
    }
    if (
        preg_match(
            '#^driver/reservations/(\d+)/check-in-otp$#',
            $route,
            $match,
        ) &&
        $method === "POST"
    ) {
        $driver = require_login(["driver"]);
        require_csrf();
        $reservationId = (int) $match[1];
        $stmt = $pdo->prepare(
            "SELECT id,starts_at FROM reservations WHERE id=? AND driver_user_id=? AND status IN ('confirmed','waiting_check_in')",
        );
        $stmt->execute([$reservationId, (int) $driver["id"]]);
        $reservation = $stmt->fetch();
        if (!$reservation) {
            fail("A check-in OTP is not available for this reservation.", 422);
        }
        $otp = (string) random_int(1000, 9999);
        $expires = (new DateTimeImmutable($reservation["starts_at"]))
            ->modify("+3 hours")
            ->format("Y-m-d H:i:s");
        $pdo->prepare(
            "INSERT INTO access_otps(reservation_id,purpose,otp_hash,expires_at) VALUES(?, 'check_in', ?, ?)",
        )->execute([$reservationId, hash("sha256", $otp), $expires]);
        audit(
            (int) $driver["id"],
            "refresh_otp",
            "reservation",
            $reservationId,
            "Driver requested a new check-in OTP.",
        );
        json_response([
            "ok" => true,
            "check_in_otp" => $otp,
            "expires_at" => $expires,
        ]);
    }
    if (
        preg_match(
            '#^driver/reservations/(\d+)/check-out-otp$#',
            $route,
            $match,
        ) &&
        $method === "POST"
    ) {
        $driver = require_login(["driver"]);
        require_csrf();
        $reservationId = (int) $match[1];
        $stmt = $pdo->prepare(
            "SELECT id,ends_at FROM reservations WHERE id=? AND driver_user_id=? AND status='active'",
        );
        $stmt->execute([$reservationId, (int) $driver["id"]]);
        $reservation = $stmt->fetch();
        if (!$reservation) {
            fail("A check-out OTP is available only after check-in.", 422);
        }
        $otp = (string) random_int(1000, 9999);
        $expires = (new DateTimeImmutable($reservation["ends_at"]))
            ->modify("+3 hours")
            ->format("Y-m-d H:i:s");
        $pdo->prepare(
            "INSERT INTO access_otps(reservation_id,purpose,otp_hash,expires_at) VALUES(?, 'check_out', ?, ?)",
        )->execute([$reservationId, hash("sha256", $otp), $expires]);
        audit(
            (int) $driver["id"],
            "refresh_otp",
            "reservation",
            $reservationId,
            "Driver requested a new check-out OTP.",
        );
        json_response([
            "ok" => true,
            "check_out_otp" => $otp,
            "expires_at" => $expires,
        ]);
    }
    /*
     * ================================================================
     * DRIVER FEATURE 07 — ISSUE REPORTING
     * POST driver/issues : validates the report, links it to the driver's
     * reservation/location, assigns the area manager, and creates a ticket.
     * GET  driver/issues : returns the driver's submitted issue history.
     * ================================================================
     */
    if ($route === "driver/issues" && $method === "POST") {
        $driver = require_login(["driver"]);
        require_csrf();
        $data = input();
        $category = value($data, "category", 30);
        $description = value($data, "description", 1500);
        $locationId = (int) ($data["location_id"] ?? 0);
        $reservationId = (int) ($data["reservation_id"] ?? 0);
        if ($reservationId) {
            $reservation = $pdo->prepare(
                "SELECT location_id FROM reservations WHERE id=? AND driver_user_id=?",
            );
            $reservation->execute([$reservationId, (int) $driver["id"]]);
            $ownedReservation = $reservation->fetch();
            if (!$ownedReservation) {
                fail("Reservation not found for your account.", 404);
            }
            $locationId = (int) $ownedReservation["location_id"];
        }
        if ($description === "" || $locationId < 1) {
            fail("Choose a parking location and describe the issue.", 422);
        }
        $allowed = [
            "space_access",
            "safety",
            "payment",
            "vehicle_damage",
            "facility",
            "other",
        ];
        if (!in_array($category, $allowed, true)) {
            $category = "other";
        }
        $managerId = first_id(
            "SELECT manager_user_id FROM manager_location_assignments WHERE location_id=? ORDER BY is_primary DESC,id ASC LIMIT 1",
            [$locationId],
        );
        $code = "IS-" . random_int(1000, 9999);
        $stmt = $pdo->prepare(
            'INSERT INTO issue_reports(ticket_code,driver_user_id,reservation_id,location_id,category,description,status,assigned_to_user_id) VALUES(?,?,?,?,?,? ,\'open\',?)',
        );
        $stmt->execute([
            $code,
            (int) $driver["id"],
            $reservationId ?: null,
            $locationId,
            $category,
            $description,
            $managerId ?: null,
        ]);
        audit(
            (int) $driver["id"],
            "create",
            "issue_report",
            (int) $pdo->lastInsertId(),
            $code,
        );
        json_response(
            [
                "ok" => true,
                "ticket_code" => $code,
                "assigned_to_manager" => (bool) $managerId,
            ],
            201,
        );
    }
    if ($route === "driver/issues-legacy" && $method === "POST") {
        $driver = require_login(["driver"]);
        require_csrf();
        $data = input();
        $category = value($data, "category", 30);
        $description = value($data, "description", 1500);
        $locationId = (int) ($data["location_id"] ?? 0);
        $reservationId = (int) ($data["reservation_id"] ?? 0);
        if ($description === "") {
            fail("Please describe the issue.", 422);
        }
        $allowed = [
            "space_access",
            "safety",
            "payment",
            "vehicle_damage",
            "facility",
            "other",
        ];
        if (!in_array($category, $allowed, true)) {
            $category = "other";
        }
        $code = "IS-" . random_int(1000, 9999);
        $stmt = $pdo->prepare(
            "INSERT INTO issue_reports(ticket_code,driver_user_id,reservation_id,location_id,category,description) VALUES(?,?,?,?,?,?)",
        );
        $stmt->execute([
            $code,
            (int) $driver["id"],
            $reservationId ?: null,
            $locationId ?: null,
            $category,
            $description,
        ]);
        audit(
            (int) $driver["id"],
            "create",
            "issue_report",
            (int) $pdo->lastInsertId(),
            $code,
        );
        json_response(["ok" => true, "ticket_code" => $code], 201);
    }
    if ($route === "driver/issues" && $method === "GET") {
        $driver = require_login(["driver"]);
        $stmt = $pdo->prepare(
            "SELECT i.*,l.name AS location_name FROM issue_reports i LEFT JOIN parking_locations l ON l.id=i.location_id WHERE i.driver_user_id=? ORDER BY i.reported_at DESC",
        );
        $stmt->execute([(int) $driver["id"]]);
        json_response(["ok" => true, "issues" => $stmt->fetchAll()]);
    }
    /*
     * ================================================================
     * DRIVER FEATURE 08 — MANAGER DIRECTORY AND MESSAGING
     * GET  driver/managers       : lists active managers and assigned locations.
     * GET  driver/conversations  : returns conversation summaries/unread counts.
     * GET/POST driver/messages   : reads and sends driver-manager messages.
     * ================================================================
     */
    if ($route === "driver/managers" && $method === "GET") {
        require_login(["driver"]);
        $sql =
            "SELECT u.id,u.full_name,u.phone,GROUP_CONCAT(DISTINCT l.name ORDER BY l.name SEPARATOR ', ') AS locations FROM users u JOIN roles r ON r.id=u.role_id LEFT JOIN manager_location_assignments a ON a.manager_user_id=u.id LEFT JOIN parking_locations l ON l.id=a.location_id WHERE r.name='manager' AND u.account_status='active' GROUP BY u.id ORDER BY u.full_name";
        json_response([
            "ok" => true,
            "managers" => $pdo->query($sql)->fetchAll(),
        ]);
    }
    if ($route === "driver/messages" && $method === "POST") {
        $driver = require_login(["driver"]);
        require_csrf();
        $data = input();
        $recipient = (int) ($data["recipient_user_id"] ?? 0);
        $body = value($data, "body", 2000);
        $reservation = (int) ($data["reservation_id"] ?? 0);
        if ($recipient < 1 || $body === "") {
            fail("Choose a parking manager and enter a message.", 422);
        }
        $check = $pdo->prepare(
            "SELECT u.id,u.full_name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=? AND r.name='manager' AND u.account_status='active'",
        );
        $check->execute([$recipient]);
        $manager = $check->fetch();
        if (!$manager) {
            fail("That parking manager is not available.", 404);
        }
        $stmt = $pdo->prepare(
            "INSERT INTO messages(reservation_id,sender_user_id,recipient_user_id,body) VALUES(?,?,?,?)",
        );
        $stmt->execute([
            $reservation ?: null,
            (int) $driver["id"],
            $recipient,
            $body,
        ]);
        notify_user(
            $pdo,
            $recipient,
            "driver_message",
            "New message from " . $driver["full_name"],
            $body,
            "#messages",
        );
        json_response(["ok" => true, "id" => (int) $pdo->lastInsertId()], 201);
    }
    if ($route === "driver/conversations" && $method === "GET") {
        $driver = require_login(["driver"]);
        $stmt = $pdo->prepare(
            "SELECT u.id,u.full_name,MAX(m.created_at) AS last_at,SUBSTRING_INDEX(GROUP_CONCAT(m.body ORDER BY m.created_at DESC SEPARATOR '|||'),'|||',1) AS last_body,SUM(m.recipient_user_id=? AND m.read_at IS NULL) AS unread FROM messages m JOIN users u ON u.id=CASE WHEN m.sender_user_id=? THEN m.recipient_user_id ELSE m.sender_user_id END WHERE m.sender_user_id=? OR m.recipient_user_id=? GROUP BY u.id ORDER BY last_at DESC",
        );
        $stmt->execute([
            (int) $driver["id"],
            (int) $driver["id"],
            (int) $driver["id"],
            (int) $driver["id"],
        ]);
        json_response(["ok" => true, "conversations" => $stmt->fetchAll()]);
    }
    if (
        ($route === "driver/messages" || $route === "manager/messages") &&
        $method === "GET"
    ) {
        $roles = $route === "driver/messages" ? ["driver"] : ["manager"];
        $user = require_login($roles);
        $otherId =
            (int) ($_GET["other_user_id"] ??
                ($route === "driver/messages" ? 2 : 3));
        $stmt = $pdo->prepare(
            "SELECT m.id,m.body,m.created_at,m.sender_user_id,m.recipient_user_id,m.read_at FROM messages m WHERE (m.sender_user_id=? AND m.recipient_user_id=?) OR (m.sender_user_id=? AND m.recipient_user_id=?) ORDER BY m.created_at",
        );
        $stmt->execute([
            (int) $user["id"],
            $otherId,
            $otherId,
            (int) $user["id"],
        ]);
        json_response(["ok" => true, "messages" => $stmt->fetchAll()]);
    }
    if (
        ($route === "driver/messages" || $route === "manager/messages") &&
        $method === "POST"
    ) {
        $roles = $route === "driver/messages" ? ["driver"] : ["manager"];
        $user = require_login($roles);
        require_csrf();
        $data = input();
        $recipient =
            (int) ($data["recipient_user_id"] ??
                ($route === "driver/messages" ? 2 : 3));
        $body = value($data, "body", 2000);
        $reservation = (int) ($data["reservation_id"] ?? 0);
        if ($body === "" || $recipient < 1) {
            fail("Message text and recipient are required.", 422);
        }
        $stmt = $pdo->prepare(
            "INSERT INTO messages(reservation_id,sender_user_id,recipient_user_id,body) VALUES(?,?,?,?)",
        );
        $stmt->execute([
            $reservation ?: null,
            (int) $user["id"],
            $recipient,
            $body,
        ]);
        json_response(["ok" => true, "id" => (int) $pdo->lastInsertId()], 201);
    }
    fail("API route not found.", 404);
} catch (PDOException $exception) {
    error_log("ParkFlow database error: " . $exception->getMessage());
    fail("Database request could not be completed.", 500);
} catch (Throwable $exception) {
    error_log("ParkFlow API error: " . $exception->getMessage());
    fail("Server request could not be completed.", 500);
}
