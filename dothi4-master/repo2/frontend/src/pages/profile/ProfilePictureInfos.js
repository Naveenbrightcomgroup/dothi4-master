import { useRef, useState } from "react";
import ProfilePicture from "../../components/profilePicture";
// import CameraAltRoundedIcon from '@mui/icons-material/CameraAltRounded';
import CameraAltIcon from '@mui/icons-material/CameraAlt';
import EditIcon from '@mui/icons-material/Edit';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
export default function ProfilePictureInfos({ profile, visitor, photos }) {
  const [show, setShow] = useState(false);
  const pRef = useRef(null);
  return (
    <div className="profile_img_wrap">
      {show && <ProfilePicture setShow={setShow} pRef={pRef} photos={photos} />}
      <div className="profile_w_left">
        <div className="profile_w_img">
          <div
            className="profile_w_bg"
            ref={pRef}
            style={{
              backgroundSize: "cover",
              backgroundImage: `url(${profile.picture})`,
            }}
          ></div>
          {!visitor && (
            <div
              className="profile_circle hover1"
              onClick={() => setShow(true)}
            >
              {/* <i className="camera_filled_icon"></i> */}
              {/* <CameraAltRoundedIcon style={{fontSize:"small"}}  /> */}
              {/* <FontAwesomeIcon icon={faCamera} />             */}
              <CameraAltIcon />
              
              </div>
          )}
        </div>
        <div className="profile_w_col">
          <div className="profile_name">
            {profile.first_name} {profile.last_name}
            {/* <div className="othername">(Othername)</div> */}
          </div>
          <div className="profile_friend_count"></div>
          <div className="profile_friend_imgs"></div>
        </div>
      </div>
      {visitor ? (
        ""
      ) : (
        <div className="profile_w_right">
                    <div className="right_logo">

          <div className="blue_btn">
            {/* <img src="../../../icons/plus.png" alt="" className="invert" /> */}
            <AddCircleOutlineIcon/>
            <span>Add to story</span>
          </div> 
          <div className="gray_btn">
            {/* <i className="edit_icon"></i> */}
            <EditIcon />
            <span>Edit profile</span>
          </div>
        </div>
        </div>
      )}
    </div>
  );
}

// 
