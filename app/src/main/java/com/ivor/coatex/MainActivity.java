package com.ivor.coatex;

import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.provider.MediaStore;
import android.text.InputFilter;
import android.text.InputType;
import android.util.Log;
import android.util.TypedValue;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.DividerItemDecoration;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.google.zxing.qrcode.encoder.ByteMatrix;
import com.google.zxing.qrcode.encoder.Encoder;
import com.google.zxing.qrcode.encoder.QRCode;
import com.ivor.coatex.adapters.ContactsAdapter;
import com.ivor.coatex.db.Contact;
import com.ivor.coatex.db.Database;
import com.ivor.coatex.service.CoatexHostService;
import com.ivor.coatex.tor.Client;
import com.ivor.coatex.tor.Notifier;
import com.ivor.coatex.tor.Server;
import com.ivor.coatex.tor.Tor;
import com.ivor.coatex.utils.Settings;
import com.ivor.coatex.utils.Util;
import com.ivor.coatex.view.TorStatusView;
import com.theartofdev.edmodo.cropper.CropImage;

import java.util.List;

import io.realm.Realm;
import io.realm.RealmResults;
import io.realm.Sort;

public class MainActivity extends AppCompatActivity {

    public static final int REQUEST_QR = 12;
    private static final String TAG = MainActivity.class.getName();

    private Tor mTor;

    private void send() {
        Client.getInstance(this).startSendPendingFriends();
    }

    private RecyclerView mRVContacts;
    public ContactsAdapter mContactsAdapter;
    private RealmResults<Contact> mContacts;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        boolean use_dark_mode = Settings.getPrefs(this).getBoolean("use_dark_mode", false);

        if (use_dark_mode) {
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES);
        } else {
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO);
        }

        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        mTor = Tor.getInstance(this);

        ContextCompat.startForegroundService(this, new Intent(this, CoatexHostService.class));

        findViewById(R.id.btnRequests).setOnClickListener(view -> startActivity(new Intent(this, RequestActivity.class)));

        mRVContacts = findViewById(R.id.rcvwContacts);

        mContacts = Realm.getDefaultInstance().where(Contact.class)
                .equalTo("incoming", 0)
                .findAll()
                .sort("lastMessageTime", Sort.DESCENDING);

        mRVContacts.setLayoutManager(new LinearLayoutManager(this));
        mContactsAdapter = new ContactsAdapter(mContacts, this, false);
        mRVContacts.setAdapter(mContactsAdapter);
        mRVContacts.setHasFixedSize(true);
        mRVContacts.addItemDecoration(new DividerItemDecoration(this, DividerItemDecoration.VERTICAL));

        updateNoDataView();

        mContacts.addChangeListener((contacts1, changeSet) -> updateNoDataView());

        Realm.getDefaultInstance().where(Contact.class)
                .notEqualTo("incoming", 0).findAll().addChangeListener((contacts, changeSet) -> setRequestsUpdate());

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(view -> {
            View v = getLayoutInflater().inflate(R.layout.dialog_connect, null);

            final AlertDialog dialog = new AlertDialog.Builder(MainActivity.this)
                    //.setTitle(R.string.add_contact)
                    .setView(v)
                    .show();

            ((TextView) v.findViewById(R.id.id)).setText(Tor.getInstance(MainActivity.this).getID());
            v.findViewById(R.id.qr_show).setOnClickListener(v1 -> {
                dialog.cancel();
                showQR();
            });
            v.findViewById(R.id.qr_scan).setOnClickListener(v12 -> {
                dialog.cancel();
                scanQR();
            });
            v.findViewById(R.id.enter_id).setOnClickListener(v13 -> {
                dialog.cancel();
                addContact();
            });
            v.findViewById(R.id.copy_my_id).setOnClickListener(v13 -> {
                dialog.cancel();
                Util.setClipboard(this, mTor.getID());
                snack("ID copied to clipboard" + mTor.getID());
            });
            v.findViewById(R.id.share_id).setOnClickListener(v14 -> {
                dialog.cancel();
//                        inviteFriend();
            });

        });

        checkBatteryOptimization();
//        checkAutoStartOption();
    }

    private void updateNoDataView() {
        findViewById(R.id.txtNoContacts).setVisibility(mContactsAdapter.getItemCount() > 0 ? View.INVISIBLE : View.VISIBLE);

        setRequestsUpdate();
    }

    private void checkAutoStartOption() {
        String manufacturer = android.os.Build.MANUFACTURER;
        try {
            Intent intent = new Intent();
            if ("xiaomi".equalsIgnoreCase(manufacturer)) {
                intent.setComponent(new ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity"));
            } else if ("oppo".equalsIgnoreCase(manufacturer)) {
                intent.setComponent(new ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity"));
            } else if ("vivo".equalsIgnoreCase(manufacturer)) {
                intent.setComponent(new ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"));
            } else if ("Letv".equalsIgnoreCase(manufacturer)) {
                intent.setComponent(new ComponentName("com.letv.android.letvsafe", "com.letv.android.letvsafe.AutobootManageActivity"));
            } else if ("Honor".equalsIgnoreCase(manufacturer)) {
                intent.setComponent(new ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity"));
            }

            List<ResolveInfo> list = getPackageManager().queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);
            if (list.size() > 0) {
                startActivity(intent);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void checkBatteryOptimization() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Intent intent = new Intent();
            String packageName = getPackageName();
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                intent.setAction(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                intent.setData(Uri.parse("package:" + packageName));
                startActivity(intent);
            }
        }
    }

    void scanQR() {
        Intent takePictureIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        startActivityForResult(takePictureIntent, REQUEST_QR);
//        new IntentIntegrator(this).initiateScan(); // `this` is the current Activity
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK)
            return;
        if (requestCode == REQUEST_QR) {
            Bitmap bitmap = (Bitmap) data.getExtras().get("data");

            int width = bitmap.getWidth(), height = bitmap.getHeight();
            int[] pixels = new int[width * height];
            bitmap.getPixels(pixels, 0, width, 0, 0, width, height);
            bitmap.recycle();
            RGBLuminanceSource source = new RGBLuminanceSource(width, height, pixels);
            BinaryBitmap bBitmap = new BinaryBitmap(new HybridBinarizer(source));
            MultiFormatReader reader = new MultiFormatReader();

            try {
                Result result = reader.decode(bBitmap);
                String str = result.getText();
                Log.i("ID", str);

                String[] tokens = str.split(" ", 3);

                if (tokens.length < 2 || !tokens[0].equals("Coatex")) {
                    snack(getString(R.string.invalid_qr_code));
                    return;
                }

                String id = tokens[1].toLowerCase();

                if (id.length() != 56) {
                    snack(getString(R.string.invalid_qr_code));
                    return;
                }

                if (Contact.hasContact(this, id)) {
                    snack(getString(R.string.contact_already_added));
                    return;
                }

                String name = "";
                if (tokens.length > 2) {
                    name = tokens[2];
                }

                addContact(id, name);

                return;
            } catch (Exception ex) {
                snack(getString(R.string.invalid_qr_code));
                ex.printStackTrace();
            }
        } else if (requestCode == CropImage.CROP_IMAGE_ACTIVITY_REQUEST_CODE) {
            CropImage.ActivityResult result = CropImage.getActivityResult(data);
            if (resultCode == RESULT_OK) {
                Uri resultUri = result.getUri();
//                setDP(resultUri);
                Database.getInstance(this).put("dp", resultUri.getPath());
                Log.d(TAG, "onActivityResult: " + resultUri.getPath());
            } else if (resultCode == CropImage.CROP_IMAGE_ACTIVITY_RESULT_ERROR_CODE) {
            }
        }
    }

    void showQR() {
        String name = Database.getInstance(this).getName();
        String txt = "Coatex " + mTor.getID() + " " + name;
        QRCode qr;
        try {
            qr = Encoder.encode(txt, ErrorCorrectionLevel.M);
        } catch (Exception ex) {
            throw new Error(ex);
        }
        ByteMatrix mat = qr.getMatrix();
        int width = mat.getWidth();
        int height = mat.getHeight();
        int[] pixels = new int[width * height];
        for (int y = 0; y < height; y++) {
            int offset = y * width;
            for (int x = 0; x < width; x++) {
                pixels[offset + x] = mat.get(x, y) != 0 ? Color.BLACK : Color.WHITE;
            }
        }
        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        bitmap.setPixels(pixels, 0, width, 0, 0, width, height);
        bitmap = Bitmap.createScaledBitmap(bitmap, bitmap.getWidth() * 8, bitmap.getHeight() * 8, false);
        ImageView view = new ImageView(this);
        view.setImageBitmap(bitmap);
        int pad = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 16, getResources().getDisplayMetrics());
        view.setPadding(pad, pad, pad, pad);
        Rect displayRectangle = new Rect();
        Window window = getWindow();
        window.getDecorView().getWindowVisibleDisplayFrame(displayRectangle);
        int s = (int) (Math.min(displayRectangle.width(), displayRectangle.height()) * 0.9);
        view.setMinimumWidth(s);
        view.setMinimumHeight(s);
        new AlertDialog.Builder(this)
                .setView(view)
                .show();
    }

    private void changeName() {
        final FrameLayout view = new FrameLayout(this);
        final EditText editText = new EditText(this);
        editText.setFilters(new InputFilter[]{new InputFilter.LengthFilter(32)});
        editText.setImeOptions(EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        editText.setSingleLine();
        editText.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PERSON_NAME | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES | InputType.TYPE_TEXT_FLAG_CAP_WORDS);
        view.addView(editText);
        int padding = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 8, getResources().getDisplayMetrics());

        final Database db = Database.getInstance(this);

        view.setPadding(padding, padding, padding, padding);
        editText.setText(db.getName());
        new AlertDialog.Builder(this)
                .setTitle(R.string.change_alias)
                .setView(view)
                .setPositiveButton(R.string.apply, (dialog, which) -> {
                    db.setName(editText.getText().toString().trim());
                    update();
                    snack(getString(R.string.alias_changed));
                })
                .setNegativeButton(R.string.cancel, (dialog, which) -> {
                }).show();
    }

    private void update() {
        runOnUiThread(() -> {
            Database db = Database.getInstance(MainActivity.this);
            getSupportActionBar().setTitle(db.getName().trim().isEmpty() ? "Anonymous" : db.getName());
            getSupportActionBar().setSubtitle(mTor.getID());
        });
    }

    @Override
    protected void onResume() {
        super.onResume();

        Tor.getInstance(this).addListener(mTorListener);
        Server.getInstance(this).addListener(mServerListener);
        update();
        send();

        Notifier.getInstance(this).onResumeActivity();

        ((TorStatusView) findViewById(R.id.torStatusView)).update();

        ContextCompat.startForegroundService(this, new Intent(this, CoatexHostService.class));
    }

    private Server.Listener mServerListener = () -> update();

    private Tor.Listener mTorListener = () -> {
        update();
        send();
    };

    @Override
    protected void onPause() {
        Notifier.getInstance(this).onPauseActivity();
        Tor.getInstance(this).removeListener(mTorListener);
        Server.getInstance(this).removeListener(mServerListener);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mContacts.removeAllChangeListeners();
    }

    void snack(String s) {
        Snackbar.make(findViewById(R.id.content), s, Snackbar.LENGTH_SHORT).show();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);

        MenuItem mi = menu.findItem(R.id.action_search);
        if (mi != null) {
            SearchView searchView = (SearchView) mi.getActionView();
            searchView.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
                @Override
                public boolean onQueryTextSubmit(String query) {
                    if (mContactsAdapter != null) {
                        mContactsAdapter.filter(query);
                    }
                    return false;
                }

                @Override
                public boolean onQueryTextChange(String newText) {
                    if (mContactsAdapter != null) {
                        mContactsAdapter.filter(newText);
                    }
                    return false;
                }
            });
            searchView.setOnCloseListener(() -> {
                if (mContactsAdapter != null) {
                    mContactsAdapter.filter(null);
                }
                Log.d(TAG, "onCreateOptionsMenu: Closing Search View");
                return false;
            });

        }

        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.action_settings:
                startActivity(new Intent(this, SettingsActivity.class));
                break;
        }
        return super.onOptionsItemSelected(item);
    }

    void addContact() {
        addContact("", "");
    }

    void addContact(String id, String alias) {

        final View view = getLayoutInflater().inflate(R.layout.dialog_add, null);
        final EditText idEd = view.findViewById(R.id.add_id);
        idEd.setText(id);
        final EditText aliasEd = view.findViewById(R.id.add_alias);
        aliasEd.setText(alias);
        final EditText aliasDescription = view.findViewById(R.id.add_description);
        AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle(R.string.add_contact)
                .setView(view)
                .setPositiveButton(R.string.ok, (dialog, which) -> {

                })
                .setNegativeButton(R.string.cancel, (dialog, which) -> {
                }).create();

        alertDialog.setOnShowListener(dialogInterface -> {

            Button button = alertDialog.getButton(AlertDialog.BUTTON_POSITIVE);
            button.setOnClickListener(view1 -> {

                String id1 = idEd.getText().toString().trim();
                if (id1.length() != 56) {
                    snack(getString(R.string.invalid_id));
                    idEd.setError(getString(R.string.invalid_id));
                    return;
                }
                if (id1.equals(mTor.getID())) {
                    snack(getString(R.string.cannot_add_self));
                    idEd.setError(getString(R.string.cannot_add_self));
                    return;
                }
                if (!Contact.addContact(MainActivity.this,
                        id1,
                        aliasEd.getText().toString().trim(),
                        aliasDescription.getText().toString().trim(),
                        null,
                        true,
                        false)) {
                    snack(getString(R.string.contact_already_present));
                    Toast.makeText(this, getString(R.string.contact_already_added), Toast.LENGTH_SHORT).show();
                    return;
                }
                snack(getString(R.string.contact_added));
                send();

                alertDialog.dismiss();
            });
        });

        alertDialog.show();
    }

    public void setRequestsUpdate() {
        int incoming = (int) Realm.getDefaultInstance().where(Contact.class).notEqualTo("incoming", 0).count();
        Button button = findViewById(R.id.btnRequests);
        if (incoming > 0) {
            button.setVisibility(View.VISIBLE);
            button.setText(getResources().getQuantityString(R.plurals.new_requests, incoming, incoming));
        } else {
            button.setVisibility(View.GONE);
        }
    }
}
